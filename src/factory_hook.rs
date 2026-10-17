//! Bounded normal Lore workflow, independent of credential lifecycle qualification.
use anyhow::{Context, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openshell_sdk::{ExecOptions, OpenShellClient, raw::proto as p};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use veoveo_qualify_openshell::harness::policy;

const WORKSPACE: &str = "vv-hook-accept";
const FACTORY: &str = "vv-qual-hook-author";
const PROVIDER: &str = "vv-hook-lore";
#[derive(Deserialize)]
struct Fixture {
    repository: String,
    assigned: String,
    other: String,
    main: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Issuer {
    public_origin: String,
    resource: String,
}
struct TemporaryKey(PathBuf);
impl Drop for TemporaryKey {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

async fn mint(root: &Path, subject: &str, repository: &str) -> anyhow::Result<String> {
    let config: Issuer = serde_json::from_slice(&std::fs::read(
        root.join("state/desktop/identity/config.json"),
    )?)?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("tls/ca/ca.crt"),
        )?)?)
        .build()?;
    let jwks: serde_json::Value = http
        .get(format!("{}/oauth/jwks.json", config.public_origin))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let keys = jwks["keys"].as_array().context("invalid signer keys")?;
    ensure!(keys.len() == 1, "expected one current adapter signer");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let header = serde_json::json!({"alg":"RS256","typ":"at+jwt","kid":keys[0]["kid"]});
    let claims = serde_json::json!({"iss":format!("{}/oauth",config.public_origin),"aud":[config.resource],"sub":subject,"client_id":"veoveo-hook-fixture","iat":now,"nbf":now,"exp":now+900,"jti":format!("hook-{}-{}",std::process::id(),SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()),"resources":[{"resource_id":format!("urc-{repository}"),"permission":["read","write"]}],"is_service_account":false});
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?)
    );
    // Trusted operator bootstrap only, mirroring the accepted read-grant helper.
    // Signing material never enters a workload, provider, image or tool output.
    let key = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--user",
            "root",
            "--cap-drop",
            "ALL",
            "--cap-add",
            "DAC_OVERRIDE",
            "--security-opt",
            "no-new-privileges",
            "-v",
            "vv-local_vv-lore-identity-secrets:/secrets:ro",
            "--entrypoint",
            "cat",
            "vv-lore:local",
            "/secrets/signing.key",
        ])
        .output()?;
    ensure!(key.status.success(), "operator signer unavailable");
    let key_path = root.join(format!(
        "state/openshell/hook-signing-{}.key",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)?;
    let temporary = TemporaryKey(key_path);
    file.write_all(&key.stdout)?;
    drop(file);
    let mut signer = Command::new("openssl")
        .args(["dgst", "-sha256", "-sign"])
        .arg(&temporary.0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    signer
        .stdin
        .take()
        .context("signer input unavailable")?
        .write_all(message.as_bytes())?;
    let signature = signer.wait_with_output()?;
    ensure!(signature.status.success(), "grant signing failed");
    Ok(format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(signature.stdout)
    ))
}

async fn install(client: &OpenShellClient, token: String) -> anyhow::Result<()> {
    let mut grpc = client.raw_grpc_fresh().await?;
    let mut provider = grpc
        .get_provider(p::GetProviderRequest {
            name: PROVIDER.into(),
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
        })
        .await?
        .into_inner()
        .provider
        .context("fixture provider missing")?;
    provider.credentials = HashMap::from([("LORE_AUTH_TOKEN".into(), token)]);
    let changed = grpc
        .update_provider(p::UpdateProviderRequest {
            provider: Some(provider),
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            ..Default::default()
        })
        .await?
        .into_inner();
    for receipt in changed.target_receipts {
        let result = openshell_sdk::provider_readiness::wait_for_provider(
            &mut grpc,
            &receipt,
            Duration::from_secs(30),
        )
        .await?;
        ensure!(
            result.outcome == openshell_sdk::provider_readiness::ProviderWaitOutcome::Complete,
            "fixture credential not installed"
        );
    }
    Ok(())
}
async fn shell(
    client: &OpenShellClient,
    command: &str,
) -> anyhow::Result<openshell_sdk::ExecResult> {
    client
        .workspace(WORKSPACE)
        .exec(
            FACTORY,
            &["/bin/sh".into(), "-c".into(), command.into()],
            ExecOptions {
                no_login_shell: true,
                timeout: Some(Duration::from_secs(20)),
                ..Default::default()
            },
        )
        .await
        .map_err(Into::into)
}
async fn ok(client: &OpenShellClient, command: &str) -> anyhow::Result<String> {
    let reply = shell(client, command).await?;
    ensure!(
        reply.stdout.len() + reply.stderr.len() < 256 * 1024,
        "fixture output exceeded bound"
    );
    ensure!(
        reply.exit_code == 0,
        "fixture command failed: {}",
        String::from_utf8_lossy(&reply.stderr)
    );
    Ok(String::from_utf8(reply.stdout)?)
}
fn lore(directory: &str, arguments: &str) -> String {
    format!(
        "cd {directory} && lore -P --identity fixture --access-token \"$LORE_AUTH_TOKEN\" {arguments}"
    )
}
#[derive(Default)]
struct CreatedResources {
    workspace: bool,
    profile: bool,
    provider: bool,
    sandbox: bool,
}

// Only resources admitted by this run in its newly created workspace are ours.
// Keep trying later cleanup steps if an earlier one fails; never sweep a workspace.
async fn cleanup(client: &OpenShellClient, created: &CreatedResources) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    if created.sandbox {
        let result = async {
            let scoped = client.workspace(WORKSPACE);
            let deleted = scoped
                .delete_sandbox(
                    FACTORY,
                    openshell_sdk::DeleteOptions {
                        allow_missing: true,
                    },
                )
                .await?;
            scoped
                .wait_deleted(
                    FACTORY,
                    Duration::from_secs(30),
                    deleted.sandbox_id.as_deref(),
                )
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            errors.push(format!("sandbox: {error}"));
        }
    }
    if created.provider {
        let result = async {
            client
                .raw_grpc_fresh()
                .await?
                .delete_provider(p::DeleteProviderRequest {
                    name: PROVIDER.into(),
                    workspace_scope: Some(p::workspace_selector(WORKSPACE)),
                    allow_missing: true,
                    ..Default::default()
                })
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            errors.push(format!("provider: {error}"));
        }
    }
    if created.profile {
        let result = async {
            client
                .raw_grpc_fresh()
                .await?
                .delete_provider_profile(p::DeleteProviderProfileRequest {
                    id: "veoveo-lore-hook-fixture".into(),
                    workspace_scope: Some(p::workspace_selector(WORKSPACE)),
                    allow_missing: true,
                    ..Default::default()
                })
                .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(error) = result {
            errors.push(format!("profile: {error}"));
        }
    }
    if created.workspace
        && let Err(error) = client
            .delete_workspace(
                WORKSPACE,
                openshell_sdk::DeleteOptions {
                    allow_missing: true,
                },
            )
            .await
    {
        errors.push(format!("workspace: {error}"));
    }
    ensure!(
        errors.is_empty(),
        "fixture cleanup failed: {}",
        errors.join("; ")
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupStage {
    Workspace,
    Profile,
    Provider,
    Sandbox,
}

fn checkpoint(stop_after: Option<SetupStage>, stage: SetupStage) -> anyhow::Result<()> {
    ensure!(
        stop_after != Some(stage),
        "injected setup failure after {stage:?}"
    );
    Ok(())
}

pub async fn run(client: &OpenShellClient, root: &Path, image: String) -> anyhow::Result<()> {
    run_inner(client, root, image, None).await
}

async fn run_inner(
    client: &OpenShellClient,
    root: &Path,
    image: String,
    stop_after: Option<SetupStage>,
) -> anyhow::Result<()> {
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(
        root.join("state/openshell/factory-hook-fixture.json"),
    )?)?;
    for id in [
        &fixture.repository,
        &fixture.assigned,
        &fixture.other,
        &fixture.main,
    ] {
        ensure!(
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid fixture ID"
        );
    }
    match client.get_workspace(WORKSPACE).await {
        Ok(_) => anyhow::bail!("fixture workspace exists; inspect it before a retry"),
        Err(openshell_sdk::SdkError::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    client.create_workspace(WORKSPACE, HashMap::new()).await?;
    let mut created = CreatedResources {
        workspace: true,
        ..Default::default()
    };
    // Setup belongs to the same finally-style cleanup path as the workflow.
    let result = tokio::time::timeout(Duration::from_secs(180), async {
        setup(client, root, &fixture, &image, stop_after, &mut created).await?;
        tokio::time::timeout(Duration::from_secs(120), workflow(client, root, &fixture)).await??;
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let cleaned = cleanup(client, &created).await;
    // Surface cleanup errors even when setup/workflow already failed.
    if let Err(error) = cleaned {
        return Err(error.context(format!("setup/workflow result: {result:?}")));
    }
    result??;
    let report = serde_json::json!({"scope":"normal-push workflow guard, not complete branch isolation","repository":fixture.repository,"image":image,"trackedFileBytes":7,"operationTimeoutSeconds":20,"workflowTimeoutSeconds":120,"setupAndWorkflowTimeoutSeconds":180,"cloneEditPush":true,"assignedPush":true,"wrongBranchMessage":true,"nativeBranchProtection":true,"humanPermissionsUnchanged":true,"factoryIsServiceAccount":false,"credentialLifecycle":"separate, unqualified","temporaryWorkspaceCleaned":true});
    let file = root.join("state/openshell/factory-hook-result.json");
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(file)?;
    output.write_all(&serde_json::to_vec_pretty(&report)?)?;
    println!(
        "Factory hook workflow passed; temporary OpenShell workload/provider/workspace removed. No renewal or revocation claim."
    );
    Ok(())
}

async fn setup(
    client: &OpenShellClient,
    root: &Path,
    fixture: &Fixture,
    image: &str,
    stop_after: Option<SetupStage>,
    created: &mut CreatedResources,
) -> anyhow::Result<()> {
    checkpoint(stop_after, SetupStage::Workspace)?;
    let profile = p::ProviderProfile {
        id: "veoveo-lore-hook-fixture".into(),
        display_name: "Ordinary Lore hook fixture".into(),
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
    let mut grpc = client.raw_grpc_fresh().await?;
    ensure!(
        grpc.import_provider_profiles(p::ImportProviderProfilesRequest {
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            profiles: vec![p::ProviderProfileImportItem {
                profile: Some(profile),
                source: "veoveo-hook-acceptance".into()
            }],
            ..Default::default()
        })
        .await?
        .into_inner()
        .imported,
        "fixture profile import rejected"
    );
    created.profile = true;
    checkpoint(stop_after, SetupStage::Profile)?;
    grpc.create_provider(p::CreateProviderRequest {
        workspace_scope: Some(p::workspace_selector(WORKSPACE)),
        provider: Some(p::Provider {
            metadata: Some(p::ObjectMeta {
                name: PROVIDER.into(),
                workspace: WORKSPACE.into(),
                ..Default::default()
            }),
            r#type: "veoveo-lore-hook-fixture".into(),
            profile_workspace: WORKSPACE.into(),
            credentials: HashMap::from([(
                "LORE_AUTH_TOKEN".into(),
                mint(root, "veoveo-hook-factory", &fixture.repository).await?,
            )]),
            ..Default::default()
        }),
        ..Default::default()
    })
    .await?;
    created.provider = true;
    checkpoint(stop_after, SetupStage::Provider)?;
    let policy = openshell_policy::parse_sandbox_policy(&serde_json::to_string(
        &policy::factory_hook(PROVIDER),
    )?)
    .map_err(|_| anyhow::anyhow!("invalid approved fixture policy"))?;
    grpc.create_sandbox(p::CreateSandboxRequest {
        name: FACTORY.into(),
        workspace_scope: Some(p::workspace_selector(WORKSPACE)),
        spec: Some(p::SandboxSpec {
            template: Some(p::SandboxTemplate {
                image: image.into(),
                ..Default::default()
            }),
            policy: Some(policy),
            providers: vec![PROVIDER.into()],
            command: vec!["/bin/sleep".into(), "infinity".into()],
            restart_policy: p::SandboxRestartPolicy::OnFailure as i32,
            ..Default::default()
        }),
        ..Default::default()
    })
    .await?;
    // Record admission before waiting: readiness failure must still delete it.
    created.sandbox = true;
    checkpoint(stop_after, SetupStage::Sandbox)?;
    client
        .workspace(WORKSPACE)
        .wait_ready(FACTORY, Duration::from_secs(120))
        .await?;
    Ok(())
}

async fn workflow(client: &OpenShellClient, root: &Path, fixture: &Fixture) -> anyhow::Result<()> {
    ok(
        client,
        "case \"$LORE_AUTH_TOKEN\" in openshell:resolve:*) printf mediated;; *) exit 90;; esac",
    )
    .await?;
    ok(
        client,
        &lore(
            "/sandbox",
            &format!(
                "repository clone grpcs://10.231.10.10:41337/{} /sandbox/edit --branch assigned",
                fixture.repository
            ),
        ),
    )
    .await?;
    ok(
        client,
        &format!(
            "if test -e /sandbox/edit/fixture.txt; then {}; fi",
            lore("/sandbox/edit", "dirty fixture.txt")
        ),
    )
    .await?;
    ok(client, "printf 'seed\n' > /sandbox/edit/fixture.txt").await?;
    ok(client, &lore("/sandbox/edit", "stage fixture.txt")).await?;
    ok(client, &lore("/sandbox/edit", "commit seed")).await?;
    ok(client, &lore("/sandbox/edit", "push")).await?;
    ok(client, "printf 'edited\n' > /sandbox/edit/fixture.txt").await?;
    ok(client, &lore("/sandbox/edit", "dirty fixture.txt")).await?;
    ok(client, &lore("/sandbox/edit", "stage fixture.txt")).await?;
    ok(client, &lore("/sandbox/edit", "commit edited")).await?;
    ok(client, &lore("/sandbox/edit", "push")).await?;
    ok(
        client,
        &lore(
            "/sandbox",
            &format!(
                "repository clone grpcs://10.231.10.10:41337/{} /sandbox/verify --branch assigned",
                fixture.repository
            ),
        ),
    )
    .await?;
    ensure!(
        ok(client, "cat /sandbox/verify/fixture.txt").await? == "edited\n",
        "independent clone content mismatch"
    );
    // Push selects the target branch's local history. Prepare that history
    // with a real commit so this assertion reaches the server's pre-push hook.
    ok(client,&lore("/sandbox",&format!("repository clone grpcs://10.231.10.10:41337/{} /sandbox/wrong --branch other-author",fixture.repository))).await?;
    ok(client, "printf 'wrong-branch\n' > /sandbox/wrong/wrong.txt").await?;
    ok(client, &lore("/sandbox/wrong", "stage wrong.txt")).await?;
    ok(
        client,
        &lore("/sandbox/wrong", "commit wrong-branch-attempt"),
    )
    .await?;
    let denied = shell(client, &lore("/sandbox/wrong", "push")).await?;
    ensure!(denied.exit_code != 0, "wrong-branch push succeeded");
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    ensure!(
        message.contains(&format!(
            "This factory is assigned to branch {}; attempted push to branch {}.",
            fixture.assigned, fixture.other
        )),
        "clear hook rejection missing: {message}"
    );
    println!(
        "Normal clone/edit/push and independent content verification passed; wrong-branch push received the explicit hook rejection"
    );
    install(
        client,
        mint(root, "veoveo-hook-protected", &fixture.repository).await?,
    )
    .await?;
    ok(
        client,
        &lore(
            "/sandbox",
            &format!(
                "repository clone grpcs://10.231.10.10:41337/{} /sandbox/protected --branch main",
                fixture.repository
            ),
        ),
    )
    .await?;
    let protection = ok(
        client,
        &lore("/sandbox/protected", "branch metadata get protect"),
    )
    .await?;
    let protected = protection
        .lines()
        .filter_map(|line| line.split_once(':'))
        .any(|(key, value)| key.trim() == "protect" && matches!(value.trim(), "1" | "true"));
    ensure!(protected, "fixture main is not protected: {protection}");
    ok(
        client,
        "printf 'blocked\n' > /sandbox/protected/protected.txt",
    )
    .await?;
    ok(client, &lore("/sandbox/protected", "stage protected.txt")).await?;
    ok(
        client,
        &lore("/sandbox/protected", "commit protected-attempt"),
    )
    .await?;
    let blocked = shell(client, &lore("/sandbox/protected", "push")).await?;
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&blocked.stdout),
        String::from_utf8_lossy(&blocked.stderr)
    );
    ensure!(
        blocked.exit_code != 0
            && message.contains("Not authorized to access repository")
            && !message.contains("This factory is assigned"),
        "native protection rejection missing: {message}"
    );
    // Stock Lore clients collapse native PermissionDenied to a generic message.
    // Read protection before the attempt and independently check the remote content.
    ok(client, &lore("/sandbox", &format!("repository clone grpcs://10.231.10.10:41337/{} /sandbox/protected-check --branch main", fixture.repository))).await?;
    ok(client, "test ! -e /sandbox/protected-check/protected.txt").await?;
    println!(
        "Factory assigned to protected main was rejected; native protection and unchanged remote content verified (stock CLI reports generic authorization denial)"
    );
    install(
        client,
        mint(root, "veoveo-hook-human", &fixture.repository).await?,
    )
    .await?;
    ok(client,&lore("/sandbox",&format!("repository clone grpcs://10.231.10.10:41337/{} /sandbox/human --branch other-author",fixture.repository))).await?;
    ok(client, "printf 'human\n' > /sandbox/human/human.txt").await?;
    ok(client, &lore("/sandbox/human", "stage human.txt")).await?;
    ok(client, &lore("/sandbox/human", "commit human-change")).await?;
    ok(client, &lore("/sandbox/human", "push")).await?;
    println!("Unassigned human identity retains ordinary push permissions");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Live regression: exercise native admissions, including a sandbox admitted
    // before readiness. No inference calls, and no resources outside our workspace.
    #[tokio::test]
    #[ignore = "requires the local authenticated OpenShell installation and fixture image"]
    async fn partial_setup_cleanup_and_existing_workspace() -> anyhow::Result<()> {
        let root = PathBuf::from(std::env::var("VV_INSTALLATION")?);
        let image = std::env::var("VV_FACTORY_IMAGE")?;
        let client = super::super::connect_as(&root, "controller").await?;
        for stage in [
            SetupStage::Workspace,
            SetupStage::Profile,
            SetupStage::Provider,
            SetupStage::Sandbox,
        ] {
            let error = run_inner(&client, &root, image.clone(), Some(stage))
                .await
                .unwrap_err();
            ensure!(
                error.to_string().contains("injected setup failure"),
                "unexpected result: {error:#}"
            );
            ensure!(
                matches!(
                    client.get_workspace(WORKSPACE).await,
                    Err(openshell_sdk::SdkError::NotFound { .. })
                ),
                "workspace leaked after {stage:?}"
            );
            println!("Cleaned partial setup after {stage:?}");
        }
        let existing = client
            .create_workspace(
                WORKSPACE,
                HashMap::from([("vv-cleanup-sentinel".into(), std::process::id().to_string())]),
            )
            .await?;
        let result = async {
            let error = run_inner(&client, &root, image, None).await.unwrap_err();
            ensure!(
                error.to_string().contains("workspace exists"),
                "unexpected result: {error:#}"
            );
            let retained = client.get_workspace(WORKSPACE).await?;
            ensure!(
                retained.name == existing.name
                    && retained.labels == existing.labels
                    && retained.phase == existing.phase,
                "pre-existing workspace was changed"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // The test created this sentinel; run_inner must have left it intact.
        client
            .delete_workspace(WORKSPACE, Default::default())
            .await?;
        result
    }
}
