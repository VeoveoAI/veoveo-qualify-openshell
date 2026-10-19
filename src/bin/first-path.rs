//! Focused native-SDK exercise for the local OpenShell cutover. No inference calls.
use anyhow::{Context as _, ensure};
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

#[path = "../forward_isolation.rs"]
mod forward_isolation;

#[path = "../lore_direct.rs"]
mod lore_direct;

#[path = "../service_ingress_harness.rs"]
mod service_ingress_harness;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    installation: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    LorePreflight,
    LoreNegative,
    LoreDirect {
        #[arg(long)]
        image: String,
        #[arg(long, default_value="all", value_parser=["all","remaining","workflow","renewal","recovery"])]
        phase: String,
    },
    Status,
    /// Prove direct forwarding and workspace denial with an existing restricted identity.
    ForwardIsolation(forward_isolation::Options),
    Factory {
        #[arg(long)]
        image: String,
        /// Replace only the disposable first-path factory after an image rebuild.
        #[arg(long)]
        replace: bool,
    },
    Boundaries,
    /// Qualify sandbox HTTPS ingress through a native bearer-passthrough exposure.
    ServiceIngress {
        #[arg(long)]
        image: String,
    },
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
    scope: Option<String>,
    issuer_ca_file: Option<PathBuf>,
}

impl Controller {
    fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_slice(
            &std::fs::read(path).context("controller configuration unavailable")?,
        )
        .context("invalid controller configuration")?;
        ensure!(
            config.scope.as_ref().is_none_or(
                |scope| !scope.trim().is_empty() && !scope.chars().any(char::is_control)
            ),
            "controller scope must be nonempty and contain no control characters"
        );
        ensure!(
            config
                .issuer_ca_file
                .as_ref()
                .is_none_or(|path| !path.as_os_str().is_empty()),
            "controller issuerCaFile must be a nonempty path when selected"
        );
        Ok(config)
    }

    fn issuer_http(&self) -> anyhow::Result<reqwest::Client> {
        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        if let Some(path) = &self.issuer_ca_file {
            let pem = std::fs::read(path).context("controller issuer CA unavailable")?;
            let certificates = reqwest::Certificate::from_pem_bundle(&pem)
                .context("invalid controller issuer CA")?;
            ensure!(
                !certificates.is_empty(),
                "invalid controller issuer CA: no certificates"
            );
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        builder
            .build()
            .context("controller issuer TLS client unavailable")
    }
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
        let mut form = vec![
            ("grant_type", "client_credentials"),
            ("client_id", self.config.client_id.as_str()),
            ("client_secret", secret.trim()),
        ];
        if let Some(scope) = &self.config.scope {
            form.push(("scope", scope.as_str()));
        }
        let response = self
            .http
            .post(&self.token_endpoint)
            .form(&form)
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
    let config = Controller::load(&root.join(format!("state/openshell/{identity}.json")))?;
    let http = config.issuer_http()?;
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
    forward_isolation::request(
        client,
        &forward_isolation::Target {
            workspace: "vv-first-private".into(),
            sandbox: "vv-first-mcp".into(),
            port: 8080,
        },
        bytes,
    )
    .await
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
    // This action must never load a machine administrator's controller file.
    if let Action::ForwardIsolation(options) = &args.command {
        options.validate()?;
        return tokio::time::timeout(Duration::from_secs(60), async {
            let client = connect_as(&args.installation, &options.identity).await?;
            forward_isolation::run(&client, options).await
        })
        .await
        .context("forward isolation exceeded 60 seconds")?;
    }
    let client = connect_as(&args.installation, "controller").await?;
    match args.command {
        Action::ForwardIsolation(_) => unreachable!("handled before controller connection"),
        Action::ServiceIngress { image } => service_ingress_harness::run(&client, image).await?,
        Action::LoreNegative => lore_direct::negative_credentials(&args.installation).await?,
        Action::LorePreflight => lore_direct::preflight(&args.installation).await?,
        Action::LoreDirect { image, phase } => {
            lore_direct::run(&client, &args.installation, image, &phase).await?
        }
        Action::Status => {
            client.list_all_sandboxes(Default::default()).await?;
            println!("Native Rust SDK authorized through verified TLS and OIDC");
        }
        Action::Factory { image, replace } => {
            lore_direct::create_smoke(&client, &args.installation, image, replace).await?
        }
        Action::Boundaries => {
            let script = r#"case "$LORE_AUTH_TOKEN" in openshell:resolve:*) ;; *) exit 90;; esac
for p in /var/run/docker.sock /etc/veoveo/signing.key /secrets/signing.key /gateway/state/gateway /Users/rozgo/.config/openshell; do
  test ! -r "$p" || exit 91
done
timeout 3 /bin/bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && exit 92
timeout 3 /bin/bash -c 'exec 3<>/dev/tcp/auth.localhost/8443' && exit 93
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
            let environment = String::from_utf8(result.stdout)?;
            ensure!(
                result.exit_code == 0
                    && environment
                        .lines()
                        .filter(|line| line.starts_with("LORE_AUTH_TOKEN="))
                        .all(|line| line.starts_with("LORE_AUTH_TOKEN=openshell:resolve:")),
                "native reference missing"
            );
            for identity in lore_direct::load(&args.installation)?.clients.values() {
                let secret = std::fs::read_to_string(&identity.secret_file)?;
                ensure!(
                    !environment.contains(secret.trim()),
                    "IdP client secret found in workload environment"
                );
            }
            ensure!(
                !environment
                    .lines()
                    .any(|line| line
                        .split_once('=')
                        .is_some_and(|(_, value)| value.starts_with("eyJ")
                            && value.matches('.').count() == 2)),
                "JWT found in workload environment"
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
            let identity = lore_direct::load(&args.installation)?.clients["smoke"]
                .subject
                .clone();
            let command = |id: &str| {
                vec!["/bin/sh".into(),"-c".into(),
                "exec lore -P --identity \"$2\" --access-token \"$LORE_AUTH_TOKEN\" repository info \"$1\"".into(),"sh".into(),
                format!("{}/{id}", bootstrap.lore_endpoint.trim_end_matches('/')),identity.clone()]
            };
            let options = || ExecOptions {
                timeout: Some(Duration::from_secs(20)),
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

#[cfg(test)]
mod controller_inputs {
    use super::*;
    use axum::{Form, Json, Router, extract::State, http::StatusCode, routing::post};
    use serde_json::json;
    use std::{
        fs::OpenOptions,
        io::Write as _,
        os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        directory: PathBuf,
    }

    impl Fixture {
        fn new() -> anyhow::Result<Self> {
            let directory = std::env::temp_dir().join(format!(
                "veoveo-controller-{}-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
            ));
            std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
            Ok(Self { directory })
        }

        fn config(
            &self,
            scope: Option<&str>,
            issuer_ca: Option<&str>,
        ) -> anyhow::Result<Controller> {
            let secret = self.directory.join("client.secret");
            if !secret.exists() {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&secret)?
                    .write_all(b"unit-controller-secret")?;
            }
            let path = self.directory.join("controller.json");
            let mut value = json!({"issuer":"https://idp.example/tenant/v2.0", "clientId":"unit-controller",
                "clientSecretFile":secret,"gateway":"https://localhost:17670","gatewayCaFile":"unused"});
            if let Some(scope) = scope {
                value["scope"] = json!(scope);
            }
            if let Some(ca) = issuer_ca {
                value["issuerCaFile"] = json!(ca);
            }
            std::fs::write(&path, serde_json::to_vec(&value)?)?;
            Controller::load(&path)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[tokio::test]
    async fn forwards_selected_scope_unchanged_and_omits_unselected_scope() -> anyhow::Result<()> {
        async fn token(
            State(expected): State<Option<String>>,
            Form(form): Form<HashMap<String, String>>,
        ) -> Json<serde_json::Value> {
            assert_eq!(form.get("scope"), expected.as_ref());
            assert_eq!(
                form.get("grant_type").map(String::as_str),
                Some("client_credentials")
            );
            assert_eq!(
                form.get("client_id").map(String::as_str),
                Some("unit-controller")
            );
            assert_eq!(
                form.get("client_secret").map(String::as_str),
                Some("unit-controller-secret")
            );
            Json(json!({"access_token":"unit-token","expires_in":60}))
        }
        let fixture = Fixture::new()?;
        for scope in [
            None,
            Some("api://unit-resource/.default"),
            Some("openid profile"),
        ] {
            let config = fixture.config(scope, None)?;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let token_endpoint = format!("http://{}/token", listener.local_addr()?);
            let app = Router::new()
                .route("/token", post(token))
                .with_state(scope.map(str::to_owned));
            let _server = Server(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
            let issuer = Issuer {
                http: config.issuer_http()?,
                config,
                token_endpoint,
            };
            assert!(issuer.refresh().await?.expires_at.is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn token_rejection_does_not_expose_credentials_or_response_body() -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        let config = fixture.config(None, None)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let token_endpoint = format!("http://{}/token", listener.local_addr()?);
        let app = Router::new().route(
            "/token",
            post(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    "unit-controller-secret unit-token",
                )
            }),
        );
        let _server = Server(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let issuer = Issuer {
            http: config.issuer_http()?,
            config,
            token_endpoint,
        };
        let error = format!(
            "{:?}",
            issuer.refresh().await.expect_err("rejection must fail")
        );
        assert!(error.contains("OIDC client authentication rejected"));
        assert!(!error.contains("unit-controller-secret") && !error.contains("unit-token"));
        Ok(())
    }

    #[test]
    fn issuer_ca_is_explicit_and_invalid_configuration_fails_clearly() -> anyhow::Result<()> {
        let fixture = Fixture::new()?;
        let config = fixture.config(None, None)?;
        assert!(config.issuer_ca_file.is_none());
        config.issuer_http()?; // No installation-local CA exists or is needed.
        for scope in ["", "  ", "scope\ninvalid"] {
            assert!(
                fixture
                    .config(Some(scope), None)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("controller scope")
            );
        }
        assert!(
            fixture
                .config(None, Some(""))
                .err()
                .unwrap()
                .to_string()
                .contains("issuerCaFile")
        );
        let missing = fixture.directory.join("absent.pem");
        assert!(
            fixture
                .config(None, missing.to_str())?
                .issuer_http()
                .err()
                .unwrap()
                .to_string()
                .contains("issuer CA unavailable")
        );
        let invalid = fixture.directory.join("invalid.pem");
        std::fs::write(&invalid, "not a certificate")?;
        assert!(
            fixture
                .config(None, invalid.to_str())?
                .issuer_http()
                .err()
                .unwrap()
                .to_string()
                .contains("invalid controller issuer CA")
        );
        Ok(())
    }
}
