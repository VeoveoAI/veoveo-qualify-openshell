//! Operator-owned native ingress fixture. No provider, host relay or public Time route.

use anyhow::{Context, Result, ensure};
use openshell_sdk::{DeleteOptions, OpenShellClient, SdkError, raw::proto as p};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use veoveo_qualify_openshell::{harness::policy, probes::service_ingress::origin, sha256_hex};

const OWNER_LABEL: &str = "veoveo.ai/qualification-run";
const SERVICE: &str = "http";
const OUTPUT_LIMIT: usize = 64 * 1024;

struct Owned {
    workspace: String,
    owner: String,
    attempted_workspace: bool,
    sandboxes: Vec<String>,
}

impl Owned {
    fn fresh() -> Self {
        let marker = sha256_hex(
            format!(
                "{}:{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )
            .as_bytes(),
        );
        Self {
            workspace: format!("vv-qual-{}", &marker[..8]),
            owner: marker[..32].into(),
            attempted_workspace: false,
            sandboxes: Vec::new(),
        }
    }

    fn labels(&self) -> HashMap<String, String> {
        HashMap::from([(OWNER_LABEL.into(), self.owner.clone())])
    }

    async fn acquire(&mut self, client: &OpenShellClient) -> Result<()> {
        match client.get_workspace(&self.workspace).await {
            Err(SdkError::NotFound { .. }) => {}
            Ok(_) => anyhow::bail!("qualification workspace already exists; no resources changed"),
            Err(error) => return Err(error.into()),
        }
        // Record the attempt before RPC: cleanup inspects labels even if admission
        // succeeds at the server but its response is lost.
        self.attempted_workspace = true;
        client
            .create_workspace(&self.workspace, self.labels())
            .await?;
        Ok(())
    }

    async fn create(
        &mut self,
        client: &OpenShellClient,
        name: &str,
        image: &str,
        policy: policy::Policy,
        command: Vec<String>,
    ) -> Result<()> {
        let scoped = client.workspace(&self.workspace);
        match scoped.get_sandbox(name).await {
            Err(SdkError::NotFound { .. }) => {}
            Ok(_) => anyhow::bail!("qualification sandbox already exists; refusing reuse"),
            Err(error) => return Err(error.into()),
        }
        let policy = openshell_policy::parse_sandbox_policy(&serde_json::to_string(&policy)?)
            .map_err(|_| anyhow::anyhow!("invalid ingress fixture policy"))?;
        self.sandboxes.push(name.into());
        client
            .raw_grpc_fresh()
            .await?
            .create_sandbox(p::CreateSandboxRequest {
                name: name.into(),
                labels: self.labels(),
                workspace_scope: Some(p::workspace_selector(&self.workspace)),
                spec: Some(p::SandboxSpec {
                    template: Some(p::SandboxTemplate {
                        image: image.into(),
                        ..Default::default()
                    }),
                    policy: Some(policy),
                    command,
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await?;
        scoped.wait_ready(name, Duration::from_secs(120)).await?;
        Ok(())
    }

    async fn cleanup(&self, client: &OpenShellClient) -> Result<()> {
        if !self.attempted_workspace {
            return Ok(());
        }
        let workspace = match client.get_workspace(&self.workspace).await {
            Ok(workspace) => workspace,
            Err(SdkError::NotFound { .. }) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        ensure!(
            workspace.labels.get(OWNER_LABEL) == Some(&self.owner),
            "cleanup refused foreign workspace metadata"
        );
        let scoped = client.workspace(&self.workspace);
        let mut failures = Vec::new();
        for name in self.sandboxes.iter().rev() {
            let cleanup = async {
                let sandbox = match scoped.get_sandbox(name).await {
                    Ok(sandbox) => sandbox,
                    Err(SdkError::NotFound { .. }) => return Ok(()),
                    Err(error) => return Err(error.into()),
                };
                ensure!(
                    sandbox.labels.get(OWNER_LABEL) == Some(&self.owner),
                    "cleanup refused foreign sandbox metadata"
                );
                client
                    .raw_grpc_fresh()
                    .await?
                    .delete_service(p::DeleteServiceRequest {
                        sandbox: name.clone(),
                        name: SERVICE.into(),
                        allow_missing: true,
                        workspace_scope: Some(p::workspace_selector(&self.workspace)),
                        ..Default::default()
                    })
                    .await?;
                let deleted = scoped
                    .delete_sandbox(
                        name,
                        DeleteOptions {
                            allow_missing: true,
                        },
                    )
                    .await?;
                scoped
                    .wait_deleted(name, Duration::from_secs(30), deleted.sandbox_id.as_deref())
                    .await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            if let Err(error) = cleanup {
                failures.push(format!("{name}: {error}"));
            }
        }
        // A failed child cleanup must never cascade through an unrelated child.
        if failures.is_empty() {
            ensure!(
                scoped
                    .list_sandboxes(Default::default())
                    .collect_all()
                    .await?
                    .is_empty(),
                "cleanup refused workspace containing an unowned or pending sandbox"
            );
            client
                .delete_workspace(
                    &self.workspace,
                    DeleteOptions {
                        allow_missing: true,
                    },
                )
                .await?;
        }
        ensure!(
            failures.is_empty(),
            "ingress cleanup failed: {}",
            failures.join("; ")
        );
        Ok(())
    }
}

async fn expose(client: &OpenShellClient, workspace: &str, server: &str) -> Result<String> {
    let response = client
        .raw_grpc_fresh()
        .await?
        .expose_service(p::ExposeServiceRequest {
            sandbox: server.into(),
            name: SERVICE.into(),
            target_port: 8080,
            domain: true,
            authorization_mode: p::ServiceAuthorizationMode::BearerPassthrough as i32,
            workspace_scope: Some(p::workspace_selector(workspace)),
            ..Default::default()
        })
        .await?
        .into_inner();
    let endpoint = response
        .endpoint
        .context("native service response omitted endpoint")?;
    ensure!(
        endpoint.sandbox == server
            && endpoint.name == SERVICE
            && endpoint.target_port == 8080
            && endpoint.authorization_mode == p::ServiceAuthorizationMode::BearerPassthrough as i32,
        "native exposure differs from requested fixture"
    );
    // Require HTTPS as returned, never repair URL, DNS, Host or certificate trust.
    let url = origin(&response.url)?;
    ensure!(
        url.host_str()
            == Some(format!("{workspace}--{server}--{SERVICE}.openshell.localhost").as_str()),
        "returned origin does not identify the owned fixture exposure"
    );
    Ok(response.url)
}

async fn probe(
    client: &OpenShellClient,
    workspace: &str,
    sandbox: &str,
    base: &str,
    deleted: bool,
) -> Result<Value> {
    let mut command = vec![
        "/usr/local/bin/probe".into(),
        "service-ingress".into(),
        "--base".into(),
        base.into(),
    ];
    if deleted {
        command.push("--deleted".into());
    }
    let mut request = p::ExecSandboxRequest {
        workspace_scope: Some(p::workspace_selector(workspace)),
        sandbox: sandbox.into(),
        command,
        no_login_shell: true,
        ..Default::default()
    };
    request
        .execution_timeout
        .get_or_insert_with(Default::default)
        .seconds = 120;
    tokio::time::timeout(Duration::from_secs(130), async {
        let mut stream = client
            .raw_grpc_fresh()
            .await?
            .exec_sandbox(request)
            .await?
            .into_inner();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        while let Some(event) = stream.message().await? {
            match event.payload {
                Some(p::exec_sandbox_event::Payload::Stdout(chunk)) => stdout.extend(chunk.data),
                Some(p::exec_sandbox_event::Payload::Stderr(chunk)) => stderr.extend(chunk.data),
                Some(p::exec_sandbox_event::Payload::Exit(result)) => exit = Some(result.exit_code),
                None => {}
            }
            ensure!(
                stdout.len() + stderr.len() <= OUTPUT_LIMIT,
                "probe output exceeds bound"
            );
        }
        ensure!(
            exit == Some(0),
            "ingress probe failed ({exit:?}): {}",
            String::from_utf8_lossy(&stderr)
        );
        Ok(serde_json::from_slice(&stdout)?)
    })
    .await
    .context("ingress probe exceeded execution deadline")?
}

async fn scenario(client: &OpenShellClient, image: &str, owned: &mut Owned) -> Result<Value> {
    owned.acquire(client).await?;
    let server = format!("{}-s", owned.workspace);
    let caller = format!("{}-c", owned.workspace);
    owned
        .create(
            client,
            &server,
            image,
            policy::server(),
            vec!["/usr/local/bin/probe".into(), "serve".into()],
        )
        .await?;
    let url = expose(client, &owned.workspace, &server).await?;
    let parsed = origin(&url)?;
    owned
        .create(
            client,
            &caller,
            image,
            policy::service_ingress(
                parsed.host_str().context("native service host")?,
                parsed
                    .port_or_known_default()
                    .context("native service port")?,
            ),
            vec!["/usr/bin/sleep".into(), "infinity".into()],
        )
        .await?;
    let first = probe(client, &owned.workspace, &caller, &url, false).await?;
    client
        .raw_grpc_fresh()
        .await?
        .delete_service(p::DeleteServiceRequest {
            sandbox: server.clone(),
            name: SERVICE.into(),
            workspace_scope: Some(p::workspace_selector(&owned.workspace)),
            ..Default::default()
        })
        .await?;
    let removed = probe(client, &owned.workspace, &caller, &url, true).await?;
    let recreated = expose(client, &owned.workspace, &server).await?;
    ensure!(recreated == url, "recreated service changed logical origin");
    let reconnected = probe(client, &owned.workspace, &caller, &url, false).await?;
    Ok(json!({"test":"native.service_ingress", "probeImage":image,
        "workspace":owned.workspace,"server":server,"client":caller,"origin":url,
        "first":first,"deleted":removed,"recreatedFreshConnection":reconnected,
        "gatewayRestartMeasured":false,"credentialRenewalMeasured":false}))
}

pub async fn run(client: &OpenShellClient, image: String) -> Result<()> {
    ensure!(
        image
            .strip_prefix("sha256:")
            .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "service-ingress requires an explicit sha256 probe image ID"
    );
    let mut owned = Owned::fresh();
    let outcome = tokio::time::timeout(
        Duration::from_secs(600),
        scenario(client, &image, &mut owned),
    )
    .await
    .context("ingress fixture exceeded scenario deadline")
    .and_then(|result| result);
    let cleanup = tokio::time::timeout(Duration::from_secs(120), owned.cleanup(client))
        .await
        .context("ingress fixture cleanup exceeded deadline")
        .and_then(|result| result);
    match (outcome, cleanup) {
        (Ok(mut report), Ok(())) => {
            report["ownedResourcesCleaned"] = json!(true);
            report["observedAtUnixMs"] = json!(veoveo_qualify_openshell::now_ms());
            println!("{}", serde_json::to_string(&report)?);
            Ok(())
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("also failed cleanup: {cleanup:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ingress_names_and_ownership_markers_are_scoped_and_bounded() {
        let owned = Owned::fresh();
        for name in [
            &owned.workspace,
            &format!("{}-s", owned.workspace),
            &format!("{}-c", owned.workspace),
        ] {
            assert!(name.starts_with("vv-qual-") && name.len() <= 19);
        }
        assert_eq!(owned.labels().get(OWNER_LABEL), Some(&owned.owner));
        assert!(!owned.attempted_workspace);
        assert!(owned.sandboxes.is_empty());
    }
}
