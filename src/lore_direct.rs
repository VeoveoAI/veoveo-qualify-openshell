//! Direct IdP issuance; native OpenShell custody, refresh and lifecycle; native Lore authorization.
use anyhow::{Context, ensure};
use openshell_sdk::{ExecOptions, OpenShellClient, raw::proto as p};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use veoveo_qualify_openshell::harness::policy;

#[cfg(not(test))]
const WORKSPACE: &str = "vv-direct-accept";
#[cfg(test)]
const WORKSPACE: &str = "vv-direct-cleanup";
const TOKEN: &str = "LORE_AUTH_TOKEN";
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub issuer: String,
    pub audience: String,
    pub token_url: String,
    pub clients: HashMap<String, Identity>,
    pub fixture: Fixture,
    token_lifetime_seconds: u64,
    refresh_before_seconds: u64,
    verifier_leeway_seconds: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub client_id: String,
    client_key: String,
    pub subject: String,
    pub secret_file: String,
    pub repository: String,
    pub scope: String,
}
#[derive(Deserialize)]
pub struct Fixture {
    pub repository: String,
    pub assigned: String,
    pub other: String,
    pub main: String,
    pub forbidden: String,
}
#[derive(Deserialize)]
struct TokenReply {
    access_token: String,
    expires_in: u64,
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}
pub fn load(root: &Path) -> anyhow::Result<Config> {
    Ok(serde_json::from_slice(&std::fs::read(
        root.join("state/openshell/lore-direct/config.json"),
    )?)?)
}
fn http(root: &Path) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            root.join("tls/ca/ca.crt"),
        )?)?)
        .build()?)
}
pub fn save(root: &Path, name: &str, value: &impl Serialize) -> anyhow::Result<()> {
    use std::io::Write;
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(root.join(format!("state/openshell/lore-direct/{name}.json")))?;
    out.write_all(&serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
pub async fn preflight(root: &Path) -> anyhow::Result<()> {
    let config = load(root)?;
    let http = http(root)?;
    let discovery: serde_json::Value = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            config.issuer
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        discovery["issuer"] == config.issuer && discovery["token_endpoint"] == config.token_url,
        "OIDC discovery mismatch"
    );
    let jwks_url = discovery["jwks_uri"].as_str().context("JWKS missing")?;
    ensure!(
        reqwest::Url::parse(jwks_url)?.origin() == reqwest::Url::parse(&config.issuer)?.origin(),
        "JWKS origin mismatch"
    );
    let jwks: jsonwebtoken::jwk::JwkSet = http
        .get(jwks_url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut evidence = Vec::new();
    for (role, identity) in &config.clients {
        let secret = std::fs::read_to_string(&identity.secret_file)?;
        let reply: TokenReply = http
            .post(&config.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &identity.client_id),
                ("client_secret", secret.trim()),
                ("scope", &identity.scope),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let header = jsonwebtoken::decode_header(&reply.access_token)?;
        ensure!(
            header.typ.as_deref() == Some("at+jwt") && header.alg == jsonwebtoken::Algorithm::RS256,
            "unexpected access-token header"
        );
        let key = jwks
            .find(header.kid.as_deref().context("kid missing")?)
            .context("unknown signing key")?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_audience(&[&config.audience]);
        validation.set_issuer(&[&config.issuer]);
        validation.set_required_spec_claims(&["iss", "aud", "sub", "exp", "iat"]);
        let claims = jsonwebtoken::decode::<serde_json::Value>(
            &reply.access_token,
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?
        .claims;
        let exp = claims["exp"].as_u64().context("exp missing")?;
        let iat = claims["iat"].as_u64().context("iat missing")?;
        ensure!(
            claims["sub"] == identity.subject
                && exp > now()
                && exp - iat <= config.token_lifetime_seconds
                && reply.expires_in <= config.token_lifetime_seconds,
            "unexpected subject/lifetime"
        );
        ensure!(
            claims["resources"]
                == serde_json::json!([{"resource_id":format!("urc-{}",identity.repository),"permission":[]}]),
            "unexpected repository authority"
        );
        ensure!(
            claims["is_service_account"] != true
                && claims["openshell_scopes"].is_null()
                && claims["realm_access"].is_null(),
            "factory received privileged claims"
        );
        // Omitted scope cannot grant its repository. Unlinked scope cannot grant the smoke repository.
        for scope in [
            "".to_string(),
            format!(
                "lore-repo-{}",
                if role == "smoke" {
                    &config.fixture.repository
                } else {
                    &config.clients["smoke"].repository
                }
            ),
        ] {
            let response = http
                .post(&config.token_url)
                .form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &identity.client_id),
                    ("client_secret", secret.trim()),
                    ("scope", &scope),
                ])
                .send()
                .await?;
            if response.status().is_success() {
                let token: TokenReply = response.json().await?;
                use base64::Engine;
                let body: serde_json::Value = serde_json::from_slice(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
                        token
                            .access_token
                            .split('.')
                            .nth(1)
                            .context("malformed token")?,
                    )?,
                )?;
                ensure!(
                    body["resources"].as_array().is_none_or(Vec::is_empty),
                    "unrequested or unlinked repository was granted"
                );
            } else {
                ensure!(
                    response.status() == 400 || response.status() == 401,
                    "unexpected scope failure"
                );
            }
        }
        evidence.push(serde_json::json!({"role":role,"subject":identity.subject,"repository":identity.repository,"headerType":"at+jwt","signedLifetimeSeconds":exp-iat,"expiresInSeconds":reply.expires_in,"scopeNegativeChecks":2}));
    }
    save(
        root,
        "preflight",
        &serde_json::json!({"at":now(),"issuer":config.issuer,"signatureVerified":true,"clients":evidence}),
    )?;
    println!(
        "Direct IdP preflight passed: verified signatures, native resource grants, subjects, at+jwt, bounded expiry and omitted/unlinked scope denial"
    );
    Ok(())
}

fn profile_id(identity: &Identity) -> String {
    format!("vv-lore-{}", &identity.repository[..8])
}
async fn import_profile(
    client: &OpenShellClient,
    config: &Config,
    workspace: &str,
    identity: &Identity,
) -> anyhow::Result<()> {
    let profile = p::ProviderProfile {
        id: profile_id(identity),
        display_name: "Direct Lore repository grant".into(),
        credentials: vec![p::ProviderProfileCredential {
            name: "access_token".into(),
            env_vars: vec![TOKEN.into()],
            required: true,
            auth_style: "bearer".into(),
            header_name: "authorization".into(),
            refresh: Some(p::ProviderCredentialRefresh {
                strategy: p::ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
                token_url: config.token_url.clone(),
                scopes: vec![identity.scope.clone()],
                refresh_before: Some(
                    Duration::from_secs(config.refresh_before_seconds).try_into()?,
                ),
                max_lifetime: Some(Duration::from_secs(config.token_lifetime_seconds).try_into()?),
                material: vec![
                    p::ProviderCredentialRefreshMaterial {
                        name: "client_id".into(),
                        required: true,
                        ..Default::default()
                    },
                    p::ProviderCredentialRefreshMaterial {
                        name: "client_secret".into(),
                        required: true,
                        secret: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    match client
        .raw_grpc_fresh()
        .await?
        .get_provider_profile(p::GetProviderProfileRequest {
            id: profile.id.clone(),
            workspace_scope: Some(p::workspace_selector(workspace)),
        })
        .await
    {
        Ok(reply) => {
            let current = reply.into_inner().profile.context("profile missing")?;
            ensure!(
                current.credentials == profile.credentials && current.endpoints.is_empty(),
                "existing direct profile differs from trusted definition"
            );
            return Ok(());
        }
        Err(error) if error.code() == tonic::Code::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let result = client
        .raw_grpc_fresh()
        .await?
        .import_provider_profiles(p::ImportProviderProfilesRequest {
            workspace_scope: Some(p::workspace_selector(workspace)),
            profiles: vec![p::ProviderProfileImportItem {
                profile: Some(profile),
                source: "veoveo-direct-oidc".into(),
            }],
            ..Default::default()
        })
        .await?
        .into_inner();
    ensure!(
        result.imported,
        "direct profile import refused: {:?}",
        result.diagnostics
    );
    Ok(())
}
async fn configure_refresh(
    client: &OpenShellClient,
    _config: &Config,
    workspace: &str,
    provider: &str,
    identity: &Identity,
) -> anyhow::Result<p::ProviderCredentialRefreshStatus> {
    let secret = std::fs::read_to_string(&identity.secret_file)?;
    client
        .raw_grpc_fresh()
        .await?
        .configure_provider_refresh(p::ConfigureProviderRefreshRequest {
            workspace_scope: Some(p::workspace_selector(workspace)),
            provider: provider.into(),
            credential_key: TOKEN.into(),
            strategy: p::ProviderCredentialRefreshStrategy::Oauth2ClientCredentials as i32,
            material: HashMap::from([
                ("client_id".into(), identity.client_id.clone()),
                ("client_secret".into(), secret.trim().into()),
            ]),
            secret_material_keys: vec!["client_secret".into()],
            ..Default::default()
        })
        .await?;
    client
        .raw_grpc_fresh()
        .await?
        .rotate_provider_credential(p::RotateProviderCredentialRequest {
            workspace_scope: Some(p::workspace_selector(workspace)),
            provider: provider.into(),
            credential_key: TOKEN.into(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .status
        .context("native initial rotation status missing")
}
pub async fn status(
    client: &OpenShellClient,
    workspace: &str,
    provider: &str,
) -> anyhow::Result<p::ProviderCredentialRefreshStatus> {
    client
        .raw_grpc_fresh()
        .await?
        .get_provider_refresh_status(p::GetProviderRefreshStatusRequest {
            workspace_scope: Some(p::workspace_selector(workspace)),
            provider: provider.into(),
            credential_key: TOKEN.into(),
        })
        .await?
        .into_inner()
        .credentials
        .into_iter()
        .next()
        .context("refresh status missing")
}
async fn prepare_smoke_provider(client: &OpenShellClient, root: &Path) -> anyhow::Result<()> {
    let config = load(root)?;
    let identity = &config.clients["smoke"];
    let provider = "vv-lore-direct";
    import_profile(client, &config, "default", identity).await?;
    let mut grpc = client.raw_grpc_fresh().await?;
    match grpc
        .get_provider(p::GetProviderRequest {
            name: provider.into(),
            workspace_scope: Some(p::workspace_selector("default")),
        })
        .await
    {
        Ok(_) => {}
        Err(error) if error.code() == tonic::Code::NotFound => {
            grpc.create_provider(p::CreateProviderRequest {
                workspace_scope: Some(p::workspace_selector("default")),
                provider: Some(p::Provider {
                    metadata: Some(p::ObjectMeta {
                        name: provider.into(),
                        workspace: "default".into(),
                        ..Default::default()
                    }),
                    r#type: profile_id(identity),
                    profile_workspace: "default".into(),
                    ..Default::default()
                }),
                ..Default::default()
            })
            .await?;
        }
        Err(error) => return Err(error.into()),
    }
    configure_refresh(client, &config, "default", provider, identity).await?;
    Ok(())
}
pub async fn create_smoke(
    client: &OpenShellClient,
    root: &Path,
    image: String,
    replace: bool,
) -> anyhow::Result<()> {
    match client.get_sandbox("vv-first-factory").await {
        Ok(_) if !replace => anyhow::bail!("smoke factory exists; use --replace explicitly"),
        Ok(_) => {}
        Err(openshell_sdk::SdkError::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    prepare_smoke_provider(client, root).await?;
    let deleted = client
        .delete_sandbox(
            "vv-first-factory",
            openshell_sdk::DeleteOptions {
                allow_missing: true,
            },
        )
        .await?;
    client
        .wait_deleted(
            "vv-first-factory",
            Duration::from_secs(30),
            deleted.sandbox_id.as_deref(),
        )
        .await?;
    super::create(
        client,
        "vv-first-factory",
        "default",
        image,
        &std::fs::read_to_string(root.join("openshell/factory.yaml"))?,
        vec!["vv-lore-direct".into()],
        vec!["/bin/sleep".into(), "infinity".into()],
    )
    .await?;
    println!("Native direct-IdP smoke factory ready; RPC policy remains read-only");
    Ok(())
}
pub async fn sync_smoke(client: &OpenShellClient, root: &Path) -> anyhow::Result<()> {
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("openshell/component-lock.json"))?)?;
    let image = lock["localValidation"]["images"]["veoveo/factory:local"]
        .as_str()
        .context("pinned factory image missing")?;
    create_smoke(client, root, image.into(), true).await
}

#[derive(Default)]
struct Owned {
    workspace: bool,
    profiles: Vec<String>,
    providers: Vec<String>,
    sandboxes: Vec<String>,
    client_change: Option<ClientEnabledChange>,
    #[cfg(test)]
    fail_after: Option<&'static str>,
}
impl Owned {
    async fn restore_client(&self, root: &Path, config: &Config) -> anyhow::Result<()> {
        if let Some(change) = &self.client_change {
            // Cleanup may run after the short-lived admin token has expired.
            let admin = ClientAdmin::connect(root, config, &change.role).await?;
            change.restore(&admin).await?;
        }
        Ok(())
    }
    fn checkpoint(&self, _stage: &str) -> anyhow::Result<()> {
        #[cfg(test)]
        ensure!(
            self.fail_after != Some(_stage),
            "injected failure after {_stage}"
        );
        Ok(())
    }
    async fn cleanup(&self, client: &OpenShellClient) -> anyhow::Result<()> {
        let mut errors = Vec::new();
        for name in self.sandboxes.iter().rev() {
            let result = async {
                let scoped = client.workspace(WORKSPACE);
                let deleted = scoped
                    .delete_sandbox(
                        name,
                        openshell_sdk::DeleteOptions {
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
            if let Err(error) = result {
                errors.push(format!("sandbox {name}: {error}"));
            }
        }
        for name in self.providers.iter().rev() {
            if let Err(error) = async {
                client
                    .raw_grpc_fresh()
                    .await?
                    .delete_provider(p::DeleteProviderRequest {
                        name: name.clone(),
                        workspace_scope: Some(p::workspace_selector(WORKSPACE)),
                        allow_missing: true,
                        ..Default::default()
                    })
                    .await?;
                Ok::<_, anyhow::Error>(())
            }
            .await
            {
                errors.push(format!("provider {name}: {error}"));
            }
        }
        for name in self.profiles.iter().rev() {
            if let Err(error) = async {
                client
                    .raw_grpc_fresh()
                    .await?
                    .delete_provider_profile(p::DeleteProviderProfileRequest {
                        id: name.clone(),
                        workspace_scope: Some(p::workspace_selector(WORKSPACE)),
                        allow_missing: true,
                        ..Default::default()
                    })
                    .await?;
                Ok::<_, anyhow::Error>(())
            }
            .await
            {
                errors.push(format!("profile {name}: {error}"));
            }
        }
        if self.workspace
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
            "owned-resource cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}
#[derive(Clone)]
struct Actor {
    name: String,
    provider: String,
    role: String,
    launch_id: String,
    sandbox_id: String,
}
async fn exec(
    client: &OpenShellClient,
    actor: &Actor,
    command: &str,
    stdin: Option<Vec<u8>>,
) -> anyhow::Result<String> {
    let result = client
        .workspace(WORKSPACE)
        .exec(
            &actor.name,
            &["/bin/sh".into(), "-c".into(), command.into()],
            ExecOptions {
                no_login_shell: true,
                timeout: Some(Duration::from_secs(20)),
                stdin,
                ..Default::default()
            },
        )
        .await?;
    ensure!(
        result.stdout.len() + result.stderr.len() < 65536,
        "command output exceeded bound"
    );
    ensure!(
        result.exit_code == 0,
        "workload command failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?)
}
async fn setup_actor(
    client: &OpenShellClient,
    config: &Config,
    image: &str,
    role: &str,
    owned: &mut Owned,
) -> anyhow::Result<Actor> {
    tokio::time::timeout(
        Duration::from_secs(180),
        setup_actor_inner(client, config, image, role, owned),
    )
    .await?
}
async fn setup_actor_inner(
    client: &OpenShellClient,
    config: &Config,
    image: &str,
    role: &str,
    owned: &mut Owned,
) -> anyhow::Result<Actor> {
    let identity = &config.clients[if role == "recover" { "b" } else { role }];
    let provider = format!("vv-direct-{role}");
    let suffix = match role {
        "protected" => "p",
        "human" => "h",
        "detach" => "d",
        "recover" => "r",
        other => other,
    };
    let name = format!("vv-qual-oidc-{suffix}");
    let profile = profile_id(identity);
    if !owned.profiles.contains(&profile) {
        import_profile(client, config, WORKSPACE, identity).await?;
        owned.profiles.push(profile.clone());
        owned.checkpoint("profile")?;
    }
    client
        .raw_grpc_fresh()
        .await?
        .create_provider(p::CreateProviderRequest {
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            provider: Some(p::Provider {
                metadata: Some(p::ObjectMeta {
                    name: provider.clone(),
                    workspace: WORKSPACE.into(),
                    ..Default::default()
                }),
                r#type: profile,
                profile_workspace: WORKSPACE.into(),
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;
    owned.providers.push(provider.clone());
    owned.checkpoint("provider")?;
    configure_refresh(client, config, WORKSPACE, &provider, identity).await?;
    let branch = match role {
        "b" | "human" | "recover" => "other-author",
        "protected" => "main",
        _ => "assigned",
    };
    let policy = openshell_policy::parse_sandbox_policy(&serde_json::to_string(
        &policy::lore_authoring(&provider, true),
    )?)
    .map_err(|_| anyhow::anyhow!("invalid approved authoring policy"))?;
    client
        .raw_grpc_fresh()
        .await?
        .create_sandbox(p::CreateSandboxRequest {
            name: name.clone(),
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            spec: Some(p::SandboxSpec {
                template: Some(p::SandboxTemplate {
                    image: image.into(),
                    ..Default::default()
                }),
                policy: Some(policy),
                providers: vec![provider.clone()],
                command: vec![
                    "/usr/local/bin/vv-lore-session".into(),
                    identity.subject.clone(),
                    format!("grpcs://10.231.10.10:41337/{}", identity.repository),
                    branch.into(),
                    format!("grpcs://10.231.10.10:41337/{}", config.fixture.forbidden),
                ],
                restart_policy: if role == "recover" {
                    p::SandboxRestartPolicy::OnFailure
                } else {
                    p::SandboxRestartPolicy::Never
                } as i32,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await?;
    owned.sandboxes.push(name.clone());
    owned.checkpoint("sandbox")?;
    let sandbox = client
        .workspace(WORKSPACE)
        .wait_ready(&name, Duration::from_secs(120))
        .await?;
    let mut actor = Actor {
        name,
        provider,
        role: role.into(),
        launch_id: String::new(),
        sandbox_id: sandbox.id,
    };
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(text) = exec(client, &actor, "cat /sandbox/ready", None).await {
                break Ok::<_, anyhow::Error>(text);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await??;
    ensure!(
        ready.ends_with("captured-once"),
        "reference-capturing workload did not start"
    );
    // The file is only a readiness hint. A fresh reply identifies the live process.
    let reply = command_reply(client, &actor, &mut 0, "ping").await?;
    ensure!(
        reply.ok && reply.text == "captured-once",
        "workload handshake failed"
    );
    actor.launch_id = reply.launch_id;
    println!(
        "{} ready with native direct-IdP refresh and one captured reference",
        actor.name
    );
    Ok(actor)
}
struct Reply {
    ok: bool,
    text: String,
    launch_id: String,
}
fn parse_reply(id: &str, reply: &str) -> anyhow::Result<Option<Reply>> {
    let Some((header, text)) = reply.split_once('\n') else {
        return Ok(None);
    };
    let mut fields = header.split_whitespace();
    if fields.next() != Some(id) {
        return Ok(None);
    }
    let code = fields.next().context("reply status missing")?;
    let launch_id = fields.next().context("reply launch marker missing")?;
    ensure!(
        matches!(code, "0" | "1") && fields.next().is_none(),
        "invalid reply header"
    );
    ensure!(
        launch_id.len() == 64 && launch_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid launch marker"
    );
    Ok(Some(Reply {
        ok: code == "0",
        text: text.into(),
        launch_id: launch_id.into(),
    }))
}
async fn command_reply(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
    action: &str,
) -> anyhow::Result<Reply> {
    *sequence += 1;
    ensure!(*sequence <= 256, "command-count bound exceeded");
    // Setup handshakes and the main workflow have separate sequence counters.
    // Never let either consume a persisted reply from the other.
    static NEXT_REQUEST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = format!(
        "{:06}-{}",
        *sequence,
        NEXT_REQUEST.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    exec(
        client,
        actor,
        "cat > /sandbox/command",
        Some(format!("{id} {action}").into_bytes()),
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let reply = exec(
                client,
                actor,
                "cat /sandbox/reply 2>/dev/null || true",
                None,
            )
            .await?;
            if let Some(reply) = parse_reply(&id, &reply)? {
                return Ok(reply);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?
}
async fn command(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
    action: &str,
) -> anyhow::Result<(bool, String)> {
    let reply = command_reply(client, actor, sequence, action).await?;
    ensure!(
        reply.launch_id == actor.launch_id,
        "capturing workload restarted"
    );
    Ok((reply.ok, reply.text))
}
async fn succeeds(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
    action: &str,
) -> anyhow::Result<String> {
    let (ok, text) = command(client, actor, sequence, action).await?;
    ensure!(ok, "{} {action} failed: {text}", actor.name);
    Ok(text)
}
async fn denied(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
    action: &str,
) -> anyhow::Result<String> {
    let (ok, text) = command(client, actor, sequence, action).await?;
    ensure!(!ok, "{} {action} unexpectedly succeeded", actor.name);
    Ok(text)
}
fn refresh_json(status: &p::ProviderCredentialRefreshStatus) -> serde_json::Value {
    serde_json::json!({"at":now(),"status":status.status,"lastRefresh":status.last_refresh_time.as_ref().map(|t|t.seconds),"expiration":status.expiration_time.as_ref().map(|t|t.seconds),"nextRefresh":status.next_refresh_time.as_ref().map(|t|t.seconds),"failureCode":status.failure_code,"recoveryAction":status.recovery_action})
}
async fn unchanged(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
) -> anyhow::Result<()> {
    succeeds(client, actor, sequence, "ping").await?;
    ensure!(
        client
            .workspace(WORKSPACE)
            .get_sandbox(&actor.name)
            .await?
            .id
            == actor.sandbox_id,
        "sandbox replaced"
    );
    Ok(())
}
async fn wait_events(
    client: &OpenShellClient,
    actor: &Actor,
    previous: usize,
) -> anyhow::Result<usize> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let output = exec(client, actor, "cat /sandbox/notifications", None).await?;
            let count = output
                .lines()
                .filter(|line| line.starts_with("Branch pushed by "))
                .count();
            if count > previous {
                return Ok::<_, anyhow::Error>(count);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?
}
async fn subscribe(
    client: &OpenShellClient,
    actor: &Actor,
    sequence: &mut u32,
) -> anyhow::Result<()> {
    succeeds(client, actor, sequence, "subscribe").await?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if exec(client, actor, "cat /sandbox/notifications", None)
                .await?
                .contains("Subscribed to events")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}
struct ClientAdmin {
    http: reqwest::Client,
    url: String,
    token: String,
}
struct ClientEnabledChange {
    role: String,
    previous: bool,
}
impl ClientEnabledChange {
    async fn restore(&self, admin: &ClientAdmin) -> anyhow::Result<()> {
        admin.set_enabled(self.previous).await
    }
}
impl ClientAdmin {
    async fn connect(root: &Path, config: &Config, role: &str) -> anyhow::Result<Self> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Admin {
            admin_username: String,
            admin_password: String,
        }
        let admin: Admin = serde_json::from_slice(&std::fs::read(
            root.join("state/identity/credentials.json"),
        )?)?;
        let http = http(root)?;
        let origin = reqwest::Url::parse(&config.issuer)?
            .origin()
            .ascii_serialization();
        let token: TokenReply = http
            .post(format!(
                "{origin}/realms/master/protocol/openid-connect/token"
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", &admin.admin_username),
                ("password", &admin.admin_password),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Self {
            http,
            url: format!(
                "{origin}/admin/realms/veoveo/clients/{}",
                config.clients[role].client_key
            ),
            token: token.access_token,
        })
    }
    async fn enabled(&self) -> anyhow::Result<bool> {
        #[derive(Deserialize)]
        struct ClientState {
            enabled: bool,
        }
        let state: ClientState = self
            .http
            .get(&self.url)
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(state.enabled)
    }
    async fn set_enabled(&self, enabled: bool) -> anyhow::Result<()> {
        self.http
            .put(&self.url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"enabled":enabled}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }
}
async fn change_client_enabled(
    owned: &mut Owned,
    role: &str,
    admin: &ClientAdmin,
    enabled: bool,
) -> anyhow::Result<()> {
    ensure!(
        owned.client_change.is_none(),
        "fixture client already changed by this run"
    );
    let previous = admin.enabled().await?;
    if previous != enabled {
        // Record before PUT: a timeout may arrive after the IdP applied the update.
        owned.client_change = Some(ClientEnabledChange {
            role: role.into(),
            previous,
        });
        admin.set_enabled(enabled).await?;
    }
    Ok(())
}
async fn stop(client: &OpenShellClient, actor: &Actor) -> anyhow::Result<()> {
    client
        .workspace(WORKSPACE)
        .stop_sandbox(&actor.name)
        .await?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let sandbox = client.workspace(WORKSPACE).get_sandbox(&actor.name).await?;
            if sandbox.phase == openshell_sdk::SandboxPhase::Stopped {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    ensure!(
        client
            .workspace(WORKSPACE)
            .exec(&actor.name, &["/bin/true".into()], ExecOptions::default())
            .await
            .is_err(),
        "stopped sandbox still executes workload"
    );
    Ok(())
}

pub async fn run(
    client: &OpenShellClient,
    root: &Path,
    image: String,
    phase: &str,
) -> anyhow::Result<()> {
    let config = load(root)?;
    let mut owned = Owned::default();
    let mut evidence = serde_json::json!({"issuer":config.issuer,"scope":"direct IdP, native OpenShell refresh/lifecycle, native Lore authorization","image":image,"started":now(),"protectedBranch":config.fixture.main,"limits":{"fixtureFiles":16,"totalFixtureBytes":65536,"tinyPushes":32,"commandSeconds":20,"lifecycleSeconds":900,"overallSeconds":1800}});
    match client.get_workspace(WORKSPACE).await {
        Ok(_) => anyhow::bail!("qualification workspace already exists; no resources changed"),
        Err(openshell_sdk::SdkError::NotFound { .. }) => {}
        Err(error) => return Err(error.into()),
    }
    client.create_workspace(WORKSPACE, HashMap::new()).await?;
    owned.workspace = true;
    let outcome=tokio::time::timeout(Duration::from_secs(1800),async {
        owned.checkpoint("workspace")?;
        let mut sequence=0;
        if phase=="recovery" {
            let r=setup_actor(client,&config,&image,"recover",&mut owned).await?;
            recovery(client,root,&r,&mut sequence,&mut evidence).await?;
            return Ok::<_,anyhow::Error>(());
        }
        let a=tokio::time::timeout(Duration::from_secs(180),setup_actor(client,&config,&image,"a",&mut owned)).await??;
        succeeds(client,&a,&mut sequence,"read").await?;
        succeeds(client,&a,&mut sequence,"push").await?;
        let expected=exec(client,&a,"cat /sandbox/edit/session.txt",None).await?;
        ensure!(expected.len()<=32 && succeeds(client,&a,&mut sequence,"verify").await?==expected,"independent clone content mismatch");
        let rejected=denied(client,&a,&mut sequence,"wrong").await?;
        ensure!(rejected.contains(&format!("This factory is assigned to branch {}; attempted push to branch {}.",config.fixture.assigned,config.fixture.other)),"explicit branch hook message missing: {rejected}");
        denied(client,&a,&mut sequence,"forbidden").await?;
        let protected=setup_actor(client,&config,&image,"protected",&mut owned).await?;
        let metadata=succeeds(client,&protected,&mut sequence,"protection").await?;ensure!(metadata.contains("protect") && metadata.contains('1'),"native protection missing");
        let rejection=denied(client,&protected,&mut sequence,"protected").await?;ensure!(rejection.contains("Not authorized") && !rejection.contains("This factory"),"native protection not preserved");
        let human=setup_actor(client,&config,&image,"human",&mut owned).await?;succeeds(client,&human,&mut sequence,"push").await?;
        stop(client,&protected).await?;stop(client,&human).await?;
        evidence["workflow"]=serde_json::json!({"cloneEditPushAndContent":"pass","wrongBranchCommittedPush":"pass","protectedBranch":"pass","unassignedHuman":"pass","ungrantedRepository":"denied"});save(root,"progress",&evidence)?;
        println!("Direct-issuer normal Lore workflow passed, including hook, native protection and ordinary human push");
        if phase=="workflow" {return Ok::<_,anyhow::Error>(());}
        let b=setup_actor(client,&config,&image,"b",&mut owned).await?;
        lifecycle(client,root,&config,&image,&a,&b,&mut owned,&mut sequence,&mut evidence,phase).await?;
        Ok(())
    }).await;
    let cleaned = owned.cleanup(client).await;
    // No IdP requests for recovery/workflow or a failure before we changed a client.
    let restored = owned.restore_client(root, &config).await;
    if let Err(error) = cleaned {
        return Err(error.context(format!("qualification outcome: {outcome:?}")));
    }
    restored?;
    outcome??;
    evidence["finished"] = now().into();
    evidence["ownedResourcesCleaned"] = true.into();
    evidence["phase"] = phase.into();
    save(root, &format!("{phase}-result"), &evidence)?;
    println!("Direct Lore qualification passed; temporary resources removed");
    Ok(())
}

async fn observe_event(
    client: &OpenShellClient,
    actor: &Actor,
    before: usize,
    sequence: &mut u32,
) -> anyhow::Result<bool> {
    let observed = wait_events(client, actor, before).await;
    unchanged(client, actor, sequence).await?;
    Ok(observed.is_ok())
}
async fn native_detach(
    client: &OpenShellClient,
    actor: &Actor,
) -> anyhow::Result<serde_json::Value> {
    let mut grpc = client.raw_grpc_fresh().await?;
    // First prove the native precondition; this rejection must not be called a revocation.
    let rejected = grpc
        .detach_sandbox_provider(p::DetachSandboxProviderRequest {
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            sandbox: actor.name.clone(),
            provider: actor.provider.clone(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    ensure!(
        rejected.code() == tonic::Code::FailedPrecondition
            && rejected.message().contains("not attached"),
        "unexpected detach precondition: {rejected}"
    );
    let mut policy = serde_json::to_value(policy::lore_authoring(&actor.provider, true))?;
    policy["network_policies"]["lore"]["endpoints"][0]
        .as_object_mut()
        .context("endpoint missing")?
        .remove("credential_binding");
    let policy = openshell_policy::parse_sandbox_policy(&serde_json::to_string(&policy)?)
        .map_err(|_| anyhow::anyhow!("invalid binding removal policy"))?;
    let version = grpc
        .update_config(p::UpdateConfigRequest {
            sandbox: actor.name.clone(),
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            policy: Some(policy),
            ..Default::default()
        })
        .await?
        .into_inner()
        .version;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let observed = grpc
                .get_sandbox_policy_status(p::GetSandboxPolicyStatusRequest {
                    sandbox: actor.name.clone(),
                    workspace_scope: Some(p::workspace_selector(WORKSPACE)),
                    version,
                    ..Default::default()
                })
                .await?
                .into_inner();
            if observed.active_version == version {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let requested = now();
    let receipt = grpc
        .detach_sandbox_provider(p::DetachSandboxProviderRequest {
            workspace_scope: Some(p::workspace_selector(WORKSPACE)),
            sandbox: actor.name.clone(),
            provider: actor.provider.clone(),
            ..Default::default()
        })
        .await?
        .into_inner()
        .receipt
        .context("detach receipt missing")?;
    let applied = openshell_sdk::provider_readiness::wait_for_provider(
        &mut grpc,
        &receipt,
        Duration::from_secs(30),
    )
    .await?;
    ensure!(
        applied.outcome == openshell_sdk::provider_readiness::ProviderWaitOutcome::Complete
            && applied.status.state == p::ProviderReadinessState::Revoked as i32,
        "native revocation not applied"
    );
    Ok(
        serde_json::json!({"requested":requested,"applied":now(),"receiptId":receipt.receipt_id,"state":"REVOKED","bindingRemovalPolicyVersion":version,"scope":"native binding removal followed by applied detach; not detach-only isolation"}),
    )
}
#[allow(clippy::too_many_arguments)]
async fn lifecycle(
    client: &OpenShellClient,
    root: &Path,
    config: &Config,
    image: &str,
    a: &Actor,
    b: &Actor,
    owned: &mut Owned,
    sequence: &mut u32,
    evidence: &mut serde_json::Value,
    phase: &str,
) -> anyhow::Result<()> {
    if phase != "remaining" {
        let initial = status(client, WORKSPACE, &a.provider).await?;
        let original_exp = initial
            .expiration_time
            .as_ref()
            .context("initial expiry missing")?
            .seconds as u64
            + 1;
        let initial_refresh = initial
            .last_refresh_time
            .as_ref()
            .context("initial refresh missing")?
            .seconds;
        let mut refreshes = std::collections::BTreeSet::new();
        let mut observations = vec![refresh_json(&initial)];
        println!(
            "Renewal observation started: original conservative expiry {original_exp}; no manual changes to A/B providers allowed"
        );
        tokio::time::timeout(Duration::from_secs(900), async {
            loop {
                let current = status(client, WORKSPACE, &a.provider).await?;
                let refreshed = current
                    .last_refresh_time
                    .as_ref()
                    .context("refresh time missing")?
                    .seconds;
                succeeds(client, a, sequence, "read").await?;
                succeeds(client, b, sequence, "read").await?;
                if refreshed != initial_refresh && refreshes.insert(refreshed) {
                    succeeds(client, a, sequence, "push").await?;
                    observations.push(refresh_json(&current));
                    println!(
                        "Automatic A renewal {} observed at {refreshed}",
                        refreshes.len()
                    );
                }
                if refreshes.len() >= 2 && now() > original_exp + config.verifier_leeway_seconds {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        unchanged(client, a, sequence).await?;
        unchanged(client, b, sequence).await?;
        succeeds(client, a, sequence, "push").await?;
        denied(client, a, sequence, "forbidden").await?;
        let rejected = denied(client, a, sequence, "wrong").await?;
        ensure!(
            rejected.contains(&config.fixture.assigned) && rejected.contains(&config.fixture.other),
            "renewed wrong-branch hook message missing: {rejected}"
        );
        evidence["automaticRenewal"] = serde_json::json!({"observations":observations,"automaticRefreshCount":refreshes.len(),"originalExpiryBound":original_exp,"postExpiryReconnectAt":now(),"verifierLeewaySeconds":config.verifier_leeway_seconds,"capturingProcessUnchanged":true,"processEvidence":{"method":"unique per-launch marker checked in fresh command replies","a":a.launch_id,"b":b.launch_id},"originalReferenceRetained":true,"freshCliConnections":true,"subjectAndRepoAuthorityUnchanged":true});
        save(root, "progress", evidence)?;
        println!(
            "Renewal passed across original expiry plus leeway, with at least two native renewals and unchanged process/reference"
        );

        save(root, "renewal-result", evidence)?;
    }
    if phase == "renewal" {
        return Ok(());
    }
    subscribe(client, a, sequence).await?;
    succeeds(client, b, sequence, "push").await?;
    let before = wait_events(client, a, 0).await?;
    let token_state = status(client, WORKSPACE, &a.provider).await?;
    let cutoff = token_state
        .expiration_time
        .as_ref()
        .context("last expiry missing")?
        .seconds as u64
        + 1
        + config.verifier_leeway_seconds;
    let disabled = now();
    let admin = ClientAdmin::connect(root, config, &a.role).await?;
    change_client_enabled(owned, &a.role, &admin, false).await?;
    succeeds(client, b, sequence, "push").await?;
    let event_after_disable = observe_event(client, a, before, sequence).await?;
    let mut first_denial = None;
    let mut failure = None;
    let b_initial = status(client, WORKSPACE, &b.provider)
        .await?
        .last_refresh_time
        .context("B initial refresh missing")?
        .seconds;
    let mut b_renewed = None;
    println!(
        "Only A issuance disabled at {disabled}; observing native failure and old-token cutoff {cutoff}"
    );
    tokio::time::timeout(Duration::from_secs(900), async {
        loop {
            let current = status(client, WORKSPACE, &a.provider).await?;
            let (allowed, _) = command(client, a, sequence, "read").await?;
            if !allowed && first_denial.is_none() {
                first_denial = Some(now());
            }
            if !current.failure_code.is_empty()
                && current
                    .last_error_time
                    .as_ref()
                    .is_some_and(|t| t.seconds as u64 >= disabled)
                && failure.is_none()
            {
                failure = Some(refresh_json(&current));
                println!(
                    "Native A refresh failed: {}; recovery action {}",
                    current.failure_code, current.recovery_action
                );
            }
            succeeds(client, b, sequence, "read").await?;
            let b_status = status(client, WORKSPACE, &b.provider).await?;
            if b_status
                .last_refresh_time
                .as_ref()
                .is_some_and(|t| t.seconds > b_initial)
            {
                b_renewed = Some(refresh_json(&b_status));
            }
            if now() > cutoff && failure.is_some() && b_renewed.is_some() {
                ensure!(!allowed, "A read succeeded after old-token bound");
                break;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    denied(client, a, sequence, "read").await?;
    let before_expiry = exec(client, a, "cat /sandbox/notifications", None)
        .await?
        .lines()
        .filter(|line| line.starts_with("Branch pushed by "))
        .count();
    succeeds(client, b, sequence, "push").await?;
    let event_after_expiry = observe_event(client, a, before_expiry, sequence).await?;
    stop(client, a).await?;
    let stopped = now();
    succeeds(client, b, sequence, "push").await?;
    evidence["sourceWithdrawal"] = serde_json::json!({"disabledAt":disabled,"nativeFailure":failure,"firstFreshRequestDenialAt":first_denial,"lastIssuedExpiryPlusLeewayBound":cutoff,"verifiedDenialAt":stopped,"eventAfterClientDisable":event_after_disable,"eventAfterExpiry":event_after_expiry,"sandboxStoppedAt":stopped,"noExecutionAfterStop":true,"BRemainedOperational":true});
    evidence["independentBRenewal"] = serde_json::json!(b_renewed);
    save(root, "withdrawal-result", evidence)?;
    save(root, "progress", evidence)?;
    println!(
        "Source withdrawal passed: native refresh failure, bounded fresh-request denial, measured stream behavior, native sandbox stop and independent B health"
    );

    let detached = setup_actor(client, config, image, "detach", owned).await?;
    succeeds(client, &detached, sequence, "read").await?;
    subscribe(client, &detached, sequence).await?;
    succeeds(client, b, sequence, "push").await?;
    let before = wait_events(client, &detached, 0).await?;
    let receipt = native_detach(client, &detached).await?;
    denied(client, &detached, sequence, "read").await?;
    unchanged(client, &detached, sequence).await?;
    succeeds(client, b, sequence, "push").await?;
    let event_after = observe_event(client, &detached, before, sequence).await?;
    stop(client, &detached).await?;
    succeeds(client, b, sequence, "push").await?;
    succeeds(client, b, sequence, "read").await?;
    evidence["appliedDetach"] = serde_json::json!({"receipt":receipt,"IdpClientEnabled":true,"capturedReferenceRejected":true,"capturingProcessUnchangedUntilStop":true,"processEvidence":{"method":"unique per-launch marker checked in fresh command replies","launchId":detached.launch_id},"eventAfterBindingRemovalAndDetach":event_after,"nativeStopAt":now(),"noExecutionAfterStop":true,"BRemainedOperational":true});
    save(root, "detach-result", evidence)?;
    save(root, "progress", evidence)?;
    println!(
        "Native binding removal and applied REVOKED detach passed; D stopped and B still operates"
    );
    stop(client, b).await?;
    let r = setup_actor(client, config, image, "recover", owned).await?;
    recovery(client, root, &r, sequence, evidence).await?;
    Ok(())
}

// Trusted operator probe only. Credentials cross stdin into curl's HTTP header,
// never argv, environment, image layers, agent workloads, or evidence files.
async fn operator_repository_get(
    root: &Path,
    repository: &str,
    token: &str,
) -> anyhow::Result<u32> {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    ensure!(
        repository.len() == 32 && repository.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid repository ID"
    );
    ensure!(
        token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "invalid bearer encoding"
    );
    let id = (0..16)
        .map(|i| u8::from_str_radix(&repository[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<_>, _>>()?;
    let mut frame = vec![0, 0, 0, 0, 18, 10, 16];
    frame.extend_from_slice(&id);
    let request = root.join("state/openshell/lore-direct/operator-request.grpc");
    std::fs::write(&request, frame)?;
    let mut process = Command::new("docker")
        .args([
            "run",
            "--rm",
            "-i",
            "--network",
            "vv-local_vv-local",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--mount",
        ])
        .arg(format!(
            "type=bind,source={},target=/request,readonly",
            request.display()
        ))
        .args([
            "--entrypoint",
            "/usr/bin/curl",
            "veoveo/factory:local",
            "--config",
            "-",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let config = format!(
        "silent\nshow-error\nhttp2\nmax-time = 10\nrequest = \"POST\"\nurl = \"https://10.231.10.10:41337/lore.repository.v1.RepositoryService/RepositoryGet\"\nheader = \"content-type: application/grpc\"\nheader = \"te: trailers\"\nheader = \"authorization: Bearer {token}\"\ndata-binary = \"@/request\"\ndump-header = \"-\"\noutput = \"/dev/null\"\n"
    );
    process
        .stdin
        .take()
        .context("operator stdin missing")?
        .write_all(config.as_bytes())?;
    let output = process.wait_with_output()?;
    ensure!(
        output.status.success(),
        "trusted TLS/gRPC probe failed (no credentials printed)"
    );
    let headers = String::from_utf8(output.stdout)?;
    headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .rfind(|(key, _)| key.eq_ignore_ascii_case("grpc-status"))
        .context("gRPC trailers missing")?
        .1
        .trim()
        .parse()
        .map_err(Into::into)
}
pub async fn negative_credentials(root: &Path, legacy: Option<&Path>) -> anyhow::Result<()> {
    let config = load(root)?;
    let identity = &config.clients["smoke"];
    let http = http(root)?;
    let secret = std::fs::read_to_string(&identity.secret_file)?;
    let native: TokenReply = http
        .post(&config.token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &identity.client_id),
            ("client_secret", secret.trim()),
            ("scope", &identity.scope),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    ensure!(
        operator_repository_get(root, &identity.repository, &native.access_token).await? == 0,
        "positive direct token failed trusted gRPC probe"
    );
    let controller: super::Controller = serde_json::from_slice(&std::fs::read(
        root.join("state/openshell/controller.json"),
    )?)?;
    let controller_secret = std::fs::read_to_string(controller.client_secret_file)?;
    let management: TokenReply = http
        .post(&config.token_url)
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", &controller.client_id),
            ("client_secret", controller_secret.trim()),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let management_status =
        operator_repository_get(root, &identity.repository, &management.access_token).await?;
    ensure!(
        matches!(management_status, 7 | 16),
        "management token reached Lore"
    );
    let mut report = serde_json::json!({"at":now(),"positiveDirectIdpGrpc":0,"openShellManagementBearerGrpc":management_status});
    if let Some(path) = legacy {
        let token = std::fs::read_to_string(path)?;
        use base64::Engine;
        let claims: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(
                token
                    .trim()
                    .split('.')
                    .nth(1)
                    .context("malformed legacy token")?,
            )?,
        )?;
        ensure!(
            claims["exp"].as_u64().is_some_and(|exp| exp > now()) && claims["iss"] != config.issuer,
            "legacy token is expired or uses new issuer"
        );
        let legacy_issuer = claims["iss"].as_str().context("legacy issuer missing")?;
        ensure!(
            legacy_issuer == "https://localhost:7443/oauth",
            "unexpected legacy issuer"
        );
        let old_keys: jsonwebtoken::jwk::JwkSet = serde_json::from_slice(&std::fs::read(
            root.join("state/openshell/lore-direct/retired-jwks.json"),
        )?)?;
        let header = jsonwebtoken::decode_header(token.trim())?;
        let key = old_keys
            .find(header.kid.as_deref().context("legacy kid missing")?)
            .context("legacy public key missing")?;
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[legacy_issuer]);
        validation.set_audience(&[&config.audience]);
        jsonwebtoken::decode::<serde_json::Value>(
            token.trim(),
            &jsonwebtoken::DecodingKey::from_jwk(key)?,
            &validation,
        )?;
        let rejected = operator_repository_get(root, &identity.repository, token.trim()).await?;
        ensure!(
            matches!(rejected, 7 | 16),
            "legacy signer token reached Lore"
        );
        report["validUnexpiredLegacySignerGrpc"] = rejected.into();
        report["legacySignatureVerified"] = true.into();
    }
    save(
        root,
        if legacy.is_some() {
            "legacy-negative-result"
        } else {
            "negative-credentials"
        },
        &report,
    )?;
    println!(
        "Trusted negative-credential checks passed; direct IdP works and management bearer is rejected{}",
        if legacy.is_some() {
            "; supplied legacy signer is also rejected"
        } else {
            ""
        }
    );
    Ok(())
}

async fn recovery(
    client: &OpenShellClient,
    root: &Path,
    actor: &Actor,
    sequence: &mut u32,
    evidence: &mut serde_json::Value,
) -> anyhow::Result<()> {
    succeeds(client, actor, sequence, "read").await?;
    let initial = status(client, WORKSPACE, &actor.provider).await?;
    let before = initial
        .last_refresh_time
        .as_ref()
        .context("initial recovery refresh missing")?
        .seconds;
    let restarted = now();
    ensure!(
        std::process::Command::new("brew")
            .args(["services", "restart", "openshell"])
            .output()?
            .status
            .success(),
        "native gateway restart failed"
    );
    // Control-plane reconnect is independent of a workload restart. This recovery
    // fixture has native OnFailure and an idempotent workspace-aware entry point.
    let reconnected = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            if let Ok(client) = super::connect_as(root, "controller").await
                && let Ok(sandbox) = client.workspace(WORKSPACE).get_sandbox(&actor.name).await
                && sandbox.phase == openshell_sdk::SandboxPhase::Ready
            {
                break client;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await?;
    ensure!(
        reconnected
            .workspace(WORKSPACE)
            .get_sandbox(&actor.name)
            .await?
            .id
            == actor.sandbox_id,
        "recovery replaced sandbox identity"
    );
    tokio::time::timeout(Duration::from_secs(300),async {loop {
        // A fresh command reply proves the recovered canonical workload is active.
        if let Ok(reply) = command_reply(&reconnected,actor,sequence,"read").await
            && reply.ok {
            let current=status(&reconnected,WORKSPACE,&actor.provider).await?;
            if current.last_refresh_time.as_ref().is_some_and(|t|t.seconds>before) {
                evidence["gatewayRecovery"]=serde_json::json!({"restartedAt":restarted,"measuredAt":now(),"sameSandboxIdentity":true,"workloadRestartPolicy":"OnFailure","capturingProcessRestarted":reply.launch_id!=actor.launch_id,"processEvidence":{"method":"unique per-launch marker from fresh command reply","before":actor.launch_id,"after":reply.launch_id},"storedRefreshRenewedAfterRestart":refresh_json(&current),"noProviderReconfigurationOrManualRotationAfterRestart":true});
                save(root,"progress",evidence)?;println!("Native gateway recovery passed: same sandbox identity, active recovered workload and stored automatic refresh");return Ok::<_,anyhow::Error>(());
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }}).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replies_require_a_fresh_request_and_unique_launch_marker() -> anyhow::Result<()> {
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        assert!(parse_reply("next", &format!("previous 0 {old}\nstale"))?.is_none());
        // PID-only evidence from the former fixture must fail, not silently qualify.
        assert!(parse_reply("next", "next 0\nold PID-only fixture").is_err());
        let reply = parse_reply("next", &format!("next 0 {new}\nactive"))?.unwrap();
        assert!(reply.ok);
        assert_eq!(reply.text, "active");
        assert_ne!(reply.launch_id, old);
        assert!(parse_reply("next", "next 0 42\nPID reused").is_err());
        Ok(())
    }
    #[tokio::test]
    async fn client_cleanup_restores_only_the_runs_changes() -> anyhow::Result<()> {
        use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct StateData {
            enabled: bool,
            writes: Vec<bool>,
            fail_after_apply: bool,
        }
        type Shared = Arc<Mutex<StateData>>;
        async fn read(State(state): State<Shared>) -> Json<serde_json::Value> {
            Json(serde_json::json!({"enabled":state.lock().unwrap().enabled}))
        }
        async fn write(
            State(state): State<Shared>,
            Json(body): Json<serde_json::Value>,
        ) -> StatusCode {
            let enabled = body["enabled"].as_bool().unwrap();
            let mut state = state.lock().unwrap();
            state.enabled = enabled;
            state.writes.push(enabled);
            if std::mem::take(&mut state.fail_after_apply) {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::NO_CONTENT
            }
        }
        let shared = Shared::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin = ClientAdmin {
            http: reqwest::Client::new(),
            url: format!("http://{}/client", listener.local_addr()?),
            token: "test".into(),
        };
        let app = Router::new()
            .route("/client", get(read).put(write))
            .with_state(shared.clone());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for (previous, enabled, failed) in [
            (true, false, false),
            (false, true, false),
            (false, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            *shared.lock().unwrap() = StateData {
                enabled: previous,
                fail_after_apply: failed,
                ..Default::default()
            };
            let mut owned = Owned::default();
            let result = change_client_enabled(&mut owned, "a", &admin, enabled).await;
            assert_eq!(result.is_err(), failed);
            if let Some(change) = &owned.client_change {
                assert_ne!(previous, enabled);
                assert_eq!(change.role, "a");
                change.restore(&admin).await?;
            }
            let state = shared.lock().unwrap();
            assert_eq!(state.enabled, previous);
            assert_eq!(
                state.writes,
                if previous == enabled {
                    vec![]
                } else {
                    vec![enabled, previous]
                }
            );
        }
        // Workflow/recovery and setup failure have no client mutation to restore.
        // This must not even read an admin credential file or contact the IdP.
        let config: Config = serde_json::from_value(serde_json::json!({
            "issuer":"unused","audience":"unused","tokenUrl":"unused","clients":{},
            "fixture":{"repository":"","assigned":"","other":"","main":"","forbidden":""},
            "tokenLifetimeSeconds":300,"refreshBeforeSeconds":180,"verifierLeewaySeconds":60
        }))?;
        Owned::default()
            .restore_client(Path::new("/missing-operator-state"), &config)
            .await?;
        server.abort();
        Ok(())
    }
    #[tokio::test]
    #[ignore = "restarts the local native gateway; requires direct OIDC installation; no inference"]
    async fn direct_recovery_preserves_disabled_fixture_client() -> anyhow::Result<()> {
        let root = std::path::PathBuf::from(std::env::var("VV_INSTALLATION")?);
        let image = std::env::var("VV_FACTORY_IMAGE")?;
        let config = load(&root)?;
        let client = super::super::connect_as(&root, "controller").await?;
        ensure!(
            matches!(
                client.get_workspace(WORKSPACE).await,
                Err(openshell_sdk::SdkError::NotFound { .. })
            ),
            "recovery test workspace pre-exists; untouched"
        );
        let admin = ClientAdmin::connect(&root, &config, "a").await?;
        let previous = admin.enabled().await?;
        let mut changed = Owned::default();
        let result = async {
            change_client_enabled(&mut changed, "a", &admin, false).await?;
            run(&client, &root, image, "recovery").await?;
            ensure!(
                !ClientAdmin::connect(&root, &config, "a")
                    .await?
                    .enabled()
                    .await?,
                "recovery cleanup enabled fixture A"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        // Restore only the outer test's own mutation, including on failed assertions.
        let restored = changed.restore_client(&root, &config).await;
        result?;
        restored?;
        ensure!(
            ClientAdmin::connect(&root, &config, "a")
                .await?
                .enabled()
                .await?
                == previous,
            "fixture A's original state not restored"
        );
        save(
            &root,
            "recovery-client-state-result",
            &serde_json::json!({
                "at":now(), "fixtureAEnabledBeforeRecovery":false, "fixtureAEnabledAfterRecovery":false,
                "outerTestOriginalEnabled":previous,"outerTestRestoredOriginal":true
            }),
        )?;
        Ok(())
    }
    #[tokio::test]
    #[ignore = "requires the local direct OIDC installation; no inference"]
    async fn direct_partial_setup_cleanup_and_existing_workspace() -> anyhow::Result<()> {
        let root = std::path::PathBuf::from(std::env::var("VV_INSTALLATION")?);
        let image = std::env::var("VV_FACTORY_IMAGE")?;
        let config = load(&root)?;
        let client = super::super::connect_as(&root, "controller").await?;
        ensure!(
            matches!(
                client.get_workspace(WORKSPACE).await,
                Err(openshell_sdk::SdkError::NotFound { .. })
            ),
            "cleanup test workspace pre-exists; untouched"
        );
        for stage in ["workspace", "profile", "provider", "sandbox"] {
            client.create_workspace(WORKSPACE, HashMap::new()).await?;
            let mut owned = Owned {
                workspace: true,
                fail_after: Some(stage),
                ..Default::default()
            };
            let result = async {
                owned.checkpoint("workspace")?;
                setup_actor(&client, &config, &image, "protected", &mut owned).await?;
                Ok::<_, anyhow::Error>(())
            }
            .await;
            let cleaned = owned.cleanup(&client).await;
            ensure!(
                result.is_err_and(|error| error.to_string().contains("injected failure")),
                "unexpected setup result"
            );
            cleaned?;
            ensure!(
                matches!(
                    client.get_workspace(WORKSPACE).await,
                    Err(openshell_sdk::SdkError::NotFound { .. })
                ),
                "workspace leaked after {stage}"
            );
            println!("Native direct setup cleaned after {stage}");
        }
        let before = client
            .create_workspace(
                WORKSPACE,
                HashMap::from([("vv-sentinel".into(), now().to_string())]),
            )
            .await?;
        let result = run(&client, &root, image, "workflow").await;
        let after = client.get_workspace(WORKSPACE).await?;
        let retained = before.labels == after.labels && before.name == after.name;
        client
            .delete_workspace(WORKSPACE, Default::default())
            .await?;
        ensure!(
            result.is_err_and(|error| error.to_string().contains("already exists")) && retained,
            "pre-existing workspace was not preserved"
        );
        Ok(())
    }
}
