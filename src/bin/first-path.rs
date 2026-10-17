//! Focused native-SDK exercise for the local OpenShell cutover. No inference calls.
use anyhow::ensure;
use clap::{Parser, Subcommand};
use openshell_sdk::raw::proto as p;
use openshell_sdk::{
    AuthConfig, ClientConfig, ExecOptions, OpenShellClient, Refresh, RefreshError, RefreshedToken,
};
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_stream::wrappers::ReceiverStream;

#[path = "../factory_hook.rs"]
mod factory_hook;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    installation: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    FactoryHook {
        #[arg(long)]
        image: String,
    },
    Status,
    Factory {
        #[arg(long)]
        image: String,
        /// Replace only the disposable first-path factory after an image rebuild.
        #[arg(long)]
        replace: bool,
    },
    SyncFactory,
    Boundaries,
    ServiceRecreation {
        #[arg(long)]
        image: String,
    },
    Lore {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        forbidden: String,
    },
    Service {
        #[arg(long)]
        image: String,
        #[arg(long)]
        reuse: bool,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Controller {
    issuer: String,
    client_id: String,
    client_secret_file: PathBuf,
    gateway: String,
    gateway_ca_file: PathBuf,
}
#[derive(Deserialize)]
struct Token {
    access_token: String,
    expires_in: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Bootstrap {
    lore_endpoint: String,
}

async fn sync_factory(client: &OpenShellClient, root: &std::path::Path) -> anyhow::Result<()> {
    let token = std::fs::read_to_string(root.join("state/openshell/lore.token"))?;
    let mut grpc = client.raw_grpc_fresh().await?;
    let mut provider = grpc
        .get_provider(p::GetProviderRequest {
            name: "vv-lore".into(),
            workspace_scope: Some(p::workspace_selector("default")),
        })
        .await?
        .into_inner()
        .provider
        .ok_or_else(|| anyhow::anyhow!("Lore provider missing"))?;
    provider.credentials = HashMap::from([("LORE_AUTH_TOKEN".into(), token.trim().into())]);
    let updated = grpc
        .update_provider(p::UpdateProviderRequest {
            provider: Some(provider),
            workspace_scope: Some(p::workspace_selector("default")),
            ..Default::default()
        })
        .await?
        .into_inner();
    for receipt in updated.target_receipts {
        let status = openshell_sdk::provider_readiness::wait_for_provider(
            &mut grpc,
            &receipt,
            Duration::from_secs(30),
        )
        .await?;
        ensure!(
            status.outcome == openshell_sdk::provider_readiness::ProviderWaitOutcome::Complete,
            "Lore credential update was not installed by supervisor"
        );
    }
    let policy = openshell_policy::parse_sandbox_policy(&std::fs::read_to_string(
        root.join("openshell/factory.yaml"),
    )?)
    .map_err(|_| anyhow::anyhow!("invalid approved sandbox policy"))?;
    let updated = grpc
        .update_config(p::UpdateConfigRequest {
            sandbox: "vv-first-factory".into(),
            workspace_scope: Some(p::workspace_selector("default")),
            policy: Some(policy),
            ..Default::default()
        })
        .await?
        .into_inner();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let status = grpc
                .get_sandbox_policy_status(p::GetSandboxPolicyStatusRequest {
                    sandbox: "vv-first-factory".into(),
                    workspace_scope: Some(p::workspace_selector("default")),
                    version: updated.version,
                    ..Default::default()
                })
                .await?
                .into_inner();
            if status.active_version == updated.version {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    println!(
        "Supervisor installed the Lore credential and factory policy revision {}",
        updated.version
    );
    Ok(())
}
struct Issuer {
    http: reqwest::Client,
    config: Controller,
    token_endpoint: String,
}

#[async_trait::async_trait]
impl Refresh for Issuer {
    async fn refresh(&self) -> Result<RefreshedToken, RefreshError> {
        let secret = std::fs::read_to_string(&self.config.client_secret_file)
            .map_err(|_| RefreshError::Terminal("controller credential unavailable".into()))?;
        let response = self
            .http
            .post(&self.token_endpoint)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", secret.trim()),
            ])
            .send()
            .await
            .map_err(|_| RefreshError::Transient("OIDC endpoint unavailable".into()))?;
        if !response.status().is_success() {
            return Err(RefreshError::Terminal(
                "OIDC client authentication rejected".into(),
            ));
        }
        let token: Token = response
            .json()
            .await
            .map_err(|_| RefreshError::Terminal("invalid OIDC token response".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(RefreshedToken::new(token.access_token).with_expires_at(now + token.expires_in))
    }
}

async fn connect_as(root: &std::path::Path, identity: &str) -> anyhow::Result<OpenShellClient> {
    let config: Controller = serde_json::from_slice(&std::fs::read(
        root.join(format!("state/openshell/{identity}.json")),
    )?)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("tls/ca/ca.crt"),
        )?)?)
        .build()?;
    #[derive(Deserialize)]
    struct Discovery {
        issuer: String,
        token_endpoint: String,
    }
    let document: Discovery = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            config.issuer
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(document.issuer == config.issuer, "OIDC issuer mismatch");
    let issuer_url = reqwest::Url::parse(&config.issuer)?;
    let token_url = reqwest::Url::parse(&document.token_endpoint)?;
    ensure!(
        token_url.scheme() == "https"
            && token_url.origin() == issuer_url.origin()
            && token_url.username().is_empty()
            && token_url.password().is_none()
            && token_url.fragment().is_none()
            && token_url.query().is_none(),
        "OIDC token endpoint is outside the trusted issuer origin"
    );
    let gateway = config.gateway.clone();
    let ca = std::fs::read(&config.gateway_ca_file)?;
    let issuer = Arc::new(Issuer {
        http,
        config,
        token_endpoint: document.token_endpoint,
    });
    let token = issuer.refresh().await?;
    let mut config = ClientConfig::new(gateway);
    config.ca_cert = Some(ca);
    config.auth = Some(AuthConfig::Oidc {
        token: token.access_token,
        expires_at: token.expires_at,
        refresh: Some(issuer),
    });
    Ok(OpenShellClient::connect(config).await?)
}

async fn create(
    client: &OpenShellClient,
    name: &str,
    workspace: &str,
    image: String,
    policy: &str,
    providers: Vec<String>,
    command: Vec<String>,
) -> anyhow::Result<()> {
    let policy = openshell_policy::parse_sandbox_policy(policy)
        .map_err(|_| anyhow::anyhow!("invalid approved sandbox policy"))?;
    client
        .raw_grpc_fresh()
        .await?
        .create_sandbox(p::CreateSandboxRequest {
            name: name.into(),
            workspace_scope: Some(p::workspace_selector(workspace)),
            spec: Some(p::SandboxSpec {
                template: Some(p::SandboxTemplate {
                    image,
                    ..Default::default()
                }),
                policy: Some(policy),
                providers,
                command,
                restart_policy: p::SandboxRestartPolicy::OnFailure as i32,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;
    client
        .workspace(workspace)
        .wait_ready(name, Duration::from_secs(120))
        .await?;
    Ok(())
}

async fn request(client: &OpenShellClient, bytes: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(p::TcpForwardFrame {
        payload: Some(p::tcp_forward_frame::Payload::Init(p::TcpForwardInit {
            sandbox: "vv-first-mcp".into(),
            workspace: "vv-first-private".into(),
            target: Some(p::tcp_forward_init::Target::Tcp(p::TcpRelayTarget {
                host: "127.0.0.1".into(),
                port: 8080,
            })),
            ..Default::default()
        })),
    })
    .await?;
    let mut stream = client
        .raw_grpc_fresh()
        .await?
        .forward_tcp(ReceiverStream::new(rx))
        .await?
        .into_inner();
    tx.send(p::TcpForwardFrame {
        payload: Some(p::tcp_forward_frame::Payload::Data(bytes)),
    })
    .await?;
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        while let Some(frame) = stream.message().await? {
            if let Some(p::tcp_forward_frame::Payload::Data(data)) = frame.payload {
                ensure!(
                    output.len() + data.len() <= 1024 * 1024,
                    "forward response exceeded limit"
                );
                output.extend(data);
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    drop(tx);
    Ok(output)
}

async fn recreate_service(
    client: &OpenShellClient,
    image: String,
    policy: &str,
) -> anyhow::Result<()> {
    const WORKSPACE: &str = "vv-first-private";
    match client.get_workspace(WORKSPACE).await {
        Ok(_) => {}
        Err(openshell_sdk::SdkError::NotFound { .. }) => {
            client.create_workspace(WORKSPACE, HashMap::new()).await?;
        }
        Err(error) => return Err(error.into()),
    }
    let service_client = client.workspace(WORKSPACE);
    let old = service_client
        .delete_sandbox(
            "vv-first-mcp",
            openshell_sdk::DeleteOptions {
                allow_missing: true,
            },
        )
        .await?;
    if let Some(id) = old.sandbox_id {
        service_client
            .wait_deleted("vv-first-mcp", Duration::from_secs(30), Some(&id))
            .await?;
    }
    create(
        client,
        "vv-first-mcp",
        WORKSPACE,
        image,
        policy,
        vec![],
        vec!["/usr/local/bin/probe".into(), "serve".into()],
    )
    .await?;
    Ok(())
}

fn response_json(reply: &[u8]) -> anyhow::Result<serde_json::Value> {
    ensure!(
        reply.starts_with(b"HTTP/1.1 200"),
        "private MCP request failed"
    );
    let start = reply
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("MCP response headers missing"))?
        + 4;
    let json: serde_json::Value = serde_json::from_slice(&reply[start..])?;
    ensure!(
        json["jsonrpc"] == "2.0" && json["error"].is_null() && json["result"].is_object(),
        "invalid MCP JSON-RPC response"
    );
    Ok(json)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let client = connect_as(&args.installation, "controller").await?;
    match args.command {
        Action::FactoryHook { image } => {
            factory_hook::run(&client, &args.installation, image).await?
        }
        Action::Status => {
            client.list_all_sandboxes(Default::default()).await?;
            println!("Native Rust SDK authorized through verified TLS and OIDC");
        }
        Action::Factory { image, replace } => {
            if !replace {
                let profile = p::ProviderProfile {
                    id: "veoveo-lore".into(),
                    display_name: "Veoveo Lore".into(),
                    description:
                        "Operator-provisioned repository credential; endpoint binding is mandatory"
                            .into(),
                    credentials: vec![p::ProviderProfileCredential {
                        name: "access_token".into(),
                        env_vars: vec!["LORE_AUTH_TOKEN".into()],
                        required: true,
                        auth_style: "bearer".into(),
                        header_name: "authorization".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                };
                let response = client
                    .raw_grpc_fresh()
                    .await?
                    .import_provider_profiles(p::ImportProviderProfilesRequest {
                        workspace_scope: Some(p::workspace_selector("default")),
                        profiles: vec![p::ProviderProfileImportItem {
                            profile: Some(profile),
                            source: "veoveo-installation".into(),
                        }],
                        ..Default::default()
                    })
                    .await?
                    .into_inner();
                ensure!(response.imported, "provider profile admission failed");
                let token =
                    std::fs::read_to_string(args.installation.join("state/openshell/lore.token"))?;
                client
                    .raw_grpc_fresh()
                    .await?
                    .create_provider(p::CreateProviderRequest {
                        workspace_scope: Some(p::workspace_selector("default")),
                        provider: Some(p::Provider {
                            metadata: Some(p::ObjectMeta {
                                name: "vv-lore".into(),
                                workspace: "default".into(),
                                ..Default::default()
                            }),
                            r#type: "veoveo-lore".into(),
                            profile_workspace: "default".into(),
                            credentials: HashMap::from([(
                                "LORE_AUTH_TOKEN".into(),
                                token.trim().into(),
                            )]),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })
                    .await?;
            } else {
                let deleted = client
                    .delete_sandbox("vv-first-factory", Default::default())
                    .await?;
                client
                    .wait_deleted(
                        "vv-first-factory",
                        Duration::from_secs(60),
                        deleted.sandbox_id.as_deref(),
                    )
                    .await?;
            }
            let policy = std::fs::read_to_string(args.installation.join("openshell/factory.yaml"))?;
            create(
                &client,
                "vv-first-factory",
                "default",
                image,
                &policy,
                vec!["vv-lore".into()],
                vec!["/bin/sleep".into(), "infinity".into()],
            )
            .await?;
            println!(
                "Factory ready; real Lore token remains in native OpenShell credential custody"
            );
        }
        Action::SyncFactory => sync_factory(&client, &args.installation).await?,
        Action::Boundaries => {
            let script = r#"case "$LORE_AUTH_TOKEN" in openshell:resolve:*) ;; *) exit 90;; esac
for p in /var/run/docker.sock /etc/veoveo/signing.key /secrets/signing.key /gateway/state/gateway /Users/rozgo/.config/openshell; do
  test ! -r "$p" || exit 91
done
timeout 3 /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && exit 92
timeout 3 /bin/bash -c 'exec 3<>/dev/tcp/10.231.10.13/8443' && exit 93
timeout 3 /bin/bash -c 'exec 3<>/dev/tcp/host.openshell.internal/17670' && exit 94
printf 'boundary-checks-passed\n'
"#;
            let result = client
                .exec(
                    "vv-first-factory",
                    &["/bin/sh".into(), "-c".into(), script.into()],
                    ExecOptions {
                        no_login_shell: true,
                        timeout: Some(Duration::from_secs(15)),
                        ..Default::default()
                    },
                )
                .await?;
            ensure!(
                result.exit_code == 0 && result.stdout == b"boundary-checks-passed\n",
                "factory custody or egress boundary failed"
            );
            let result = client
                .exec(
                    "vv-first-factory",
                    &["/usr/bin/env".into()],
                    ExecOptions::default(),
                )
                .await?;
            let real_token =
                std::fs::read_to_string(args.installation.join("state/openshell/lore.token"))?;
            ensure!(
                result.exit_code == 0
                    && !String::from_utf8_lossy(&result.stdout).contains(real_token.trim()),
                "real Lore credential found in workload environment"
            );
            println!(
                "Factory has only the Lore placeholder, no bootstrap/operator mounts or Docker socket; direct public and identity-administration egress denied"
            );
        }
        Action::Lore {
            repository,
            forbidden,
        } => {
            let bootstrap: Bootstrap = serde_json::from_slice(&std::fs::read(
                args.installation.join("openshell/bootstrap.json"),
            )?)?;
            let endpoint = reqwest::Url::parse(&bootstrap.lore_endpoint)?;
            ensure!(
                endpoint.scheme() == "grpcs"
                    && endpoint.host_str().is_some()
                    && endpoint.username().is_empty()
                    && endpoint.password().is_none()
                    && endpoint.query().is_none()
                    && endpoint.fragment().is_none(),
                "invalid Lore endpoint"
            );
            ensure!(
                [&repository, &forbidden]
                    .iter()
                    .all(|id| id.len() == 32 && id.bytes().all(|c| c.is_ascii_hexdigit())),
                "invalid repository identifier"
            );
            let command = |id: &str| {
                vec!["/bin/sh".into(),"-c".into(),
                "exec lore -P --identity factory --access-token \"$LORE_AUTH_TOKEN\" repository info \"$1\"".into(),"sh".into(),
                format!("{}/{id}", bootstrap.lore_endpoint.trim_end_matches('/'))]
            };
            let options = || ExecOptions {
                timeout: Some(Duration::from_secs(30)),
                no_login_shell: true,
                ..Default::default()
            };
            let allowed = client
                .exec("vv-first-factory", &command(&repository), options())
                .await?;
            ensure!(
                allowed.exit_code == 0,
                "allowed Lore command failed (exit {}): {}",
                allowed.exit_code,
                String::from_utf8_lossy(&allowed.stderr)
            );
            let denied = client
                .exec("vv-first-factory", &command(&forbidden), options())
                .await?;
            ensure!(
                denied.exit_code != 0,
                "forbidden Lore repository was accessible"
            );
            println!(
                "Lore command succeeded for assigned repository; forbidden repository rejected"
            );
            println!("{}", String::from_utf8_lossy(&allowed.stdout));
        }
        Action::ServiceRecreation { image } => {
            let policy = std::fs::read_to_string(args.installation.join("openshell/service.yaml"))?;
            let existing = match client.get_sandbox("vv-first-mcp").await {
                Ok(sandbox) => Some(sandbox.id),
                Err(openshell_sdk::SdkError::NotFound { .. }) => None,
                Err(error) => return Err(error.into()),
            };
            if existing.is_none() {
                create(
                    &client,
                    "vv-first-mcp",
                    "default",
                    image.clone(),
                    &policy,
                    vec![],
                    vec!["/usr/local/bin/probe".into(), "serve".into()],
                )
                .await?;
            }
            let sentinel = client.get_sandbox("vv-first-mcp").await?.id;
            for _ in 0..2 {
                recreate_service(&client, image.clone(), &policy).await?;
                ensure!(
                    client.get_sandbox("vv-first-mcp").await?.id == sentinel,
                    "private recreation modified the default-workspace sandbox"
                );
            }
            if existing.is_none() {
                let deleted = client
                    .delete_sandbox("vv-first-mcp", Default::default())
                    .await?;
                client
                    .wait_deleted(
                        "vv-first-mcp",
                        Duration::from_secs(30),
                        deleted.sandbox_id.as_deref(),
                    )
                    .await?;
            }
            println!(
                "Two private service recreations preserved the same-named default-workspace sandbox; test-owned sentinel cleaned up"
            );
        }
        Action::Service { image, reuse } => {
            let policy = std::fs::read_to_string(args.installation.join("openshell/service.yaml"))?;
            if !reuse {
                recreate_service(&client, image, &policy).await?;
            }
            let health = request(
                &client,
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec(),
            )
            .await?;
            ensure!(
                health.starts_with(b"HTTP/1.1 200"),
                "private service health failed"
            );
            let post = |body: &str, auth: bool| {
                format!("POST /first-mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: 2025-11-25\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                if auth {"Authorization: Bearer fixture-app-token\r\n"} else {""},body.len()).into_bytes()
            };
            let initialize = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"first-path","version":"0.1.0"}}}"#;
            let reply = request(&client, post(initialize, true)).await?;
            let json = response_json(&reply)?;
            ensure!(
                json["result"]["protocolVersion"] == "2025-11-25"
                    && json["result"]["serverInfo"]["name"] == "veoveo-first-mcp",
                "MCP initialization failed"
            );
            let notification = request(
                &client,
                post(
                    r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                    true,
                ),
            )
            .await?;
            ensure!(
                notification.starts_with(b"HTTP/1.1 202"),
                "MCP notification failed"
            );
            let tools = response_json(
                &request(
                    &client,
                    post(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, true),
                )
                .await?,
            )?;
            ensure!(
                tools["result"]["tools"][0]["name"] == "echo",
                "MCP discovery failed"
            );
            let call = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"native-openshell"}}}"#;
            let result = response_json(&request(&client, post(call, true)).await?)?;
            ensure!(
                result["result"]["content"][0]["text"] == "native-openshell"
                    && result["result"]["isError"] == false,
                "MCP tool call failed"
            );
            let denied = request(&client, post(call, false)).await?;
            ensure!(
                denied.starts_with(b"HTTP/1.1 401"),
                "application credential was not required"
            );
            let outsider = connect_as(&args.installation, "outsider").await?;
            let denied = request(&outsider, post(call, true))
                .await
                .expect_err("workspace nonmember reached private MCP");
            ensure!(
                denied
                    .downcast_ref::<tonic::Status>()
                    // Native sandbox-target authorization conceals unauthorized
                    // resources with NOT_FOUND. The owner used this exact live
                    // target successfully immediately above.
                    .is_some_and(|status| status.code() == tonic::Code::NotFound),
                "nonmember failure was not an authorization denial (gRPC code: {:?})",
                denied
                    .downcast_ref::<tonic::Status>()
                    .map(tonic::Status::code)
            );
            println!(
                "Private MCP initialized, listed and called echo through native ForwardTcp; missing application credential and OIDC workspace nonmember denied"
            );
        }
    }
    Ok(())
}
