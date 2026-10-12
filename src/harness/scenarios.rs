//! Qualification scenarios. Each rule states the behavior Veoveo relies on or a
//! documented limitation, and every outcome keeps the measurements behind it.

use super::{
    host::{self, Surreal},
    openshell::{self, Exposure, SandboxSpec},
    policy::{self, HostPorts},
    report::Outcome,
};
use crate::{client, probes};
use anyhow::Context;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

mod git;
mod peer;
mod provider;
pub use git::GitHubTarget;

pub struct Settings {
    pub run_id: String,
    pub image: String,
    pub stream_seconds: u64,
    pub transfer_mib: u64,
    pub cache_mib: u64,
    pub gpu: bool,
    pub keep: bool,
    /// Runs scenarios that can leave an undeletable record behind on the gateway.
    pub lifecycle: bool,
    /// Runs the GitHub provider scenario against these repositories.
    pub github: Option<git::GitHubTarget>,
}

const SERVER_HTTP: u16 = 8080;
const STREAM_INTERVAL_MS: u64 = 500;
const BURST_STREAMS: usize = 50;
const SAMPLE_ROWS: u64 = 2000;

fn num(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(Value::as_u64)
}

fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .map(|v| v.to_string())
        .unwrap_or_default()
}

fn streamed_cleanly(report: &Value, interval_ms: u64) -> bool {
    num(report, "/received") == num(report, "/expected")
        && report.get("error").is_none_or(Value::is_null)
        && num(report, "/max_gap_ms").is_some_and(|gap| gap <= interval_ms + 500)
}

/// Bounds a probe so a stalled stream fails its scenario instead of hanging the run.
async fn within<T>(
    seconds: u64,
    probe: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    tokio::time::timeout(Duration::from_secs(seconds), probe)
        .await
        .map_err(|_| anyhow::anyhow!("deadline of {seconds} seconds exceeded"))?
}

fn deadline(settings: &Settings) -> u64 {
    settings.stream_seconds + 120
}

struct Sandboxes {
    server: String,
    client: String,
    redap: String,
    dev: String,
    gpu: Option<String>,
}

impl Sandboxes {
    fn all(&self) -> Vec<&str> {
        let mut names = vec![
            self.server.as_str(),
            self.client.as_str(),
            self.redap.as_str(),
            self.dev.as_str(),
        ];
        names.extend(self.gpu.as_deref());
        names
    }
}

struct RunContext {
    policies: std::path::PathBuf,
    sandboxes: Sandboxes,
    ports: HostPorts,
    server_url: String,
    server_grpc_url: String,
    grpc_forward_port: u16,
    redap_url: String,
    redap_forward_port: u16,
}

pub async fn run(settings: &Settings, workdir: &Path) -> anyhow::Result<Vec<Outcome>> {
    let ports = HostPorts {
        plain_http: host::free_port()?,
        plain_grpc: host::free_port()?,
        mcp_http: host::free_port()?,
        websocket_http: host::free_port()?,
        tcp_grpc: host::free_port()?,
        surreal_inspected: host::free_port()?,
        surreal_tcp: host::free_port()?,
    };
    let servers = vec![
        host::spawn_server(ports.plain_http, ports.plain_grpc),
        host::spawn_server(ports.mcp_http, host::free_port()?),
        host::spawn_server(ports.websocket_http, host::free_port()?),
        host::spawn_server(host::free_port()?, ports.tcp_grpc),
    ];
    let surreal_container = format!("q{}-surreal", settings.run_id);
    let surreal = Surreal::start(
        &surreal_container,
        ports.surreal_inspected,
        ports.surreal_tcp,
    )
    .await?;

    let prefix = format!("q{}", settings.run_id);
    let sandboxes = Sandboxes {
        server: format!("{prefix}-server"),
        client: format!("{prefix}-client"),
        redap: format!("{prefix}-redap"),
        dev: format!("{prefix}-dev"),
        gpu: settings.gpu.then(|| format!("{prefix}-gpu")),
    };
    let outcome = async {
        let context = setup(settings, workdir, ports, &sandboxes, &surreal).await?;
        Ok::<_, anyhow::Error>(scenarios(settings, workdir, &context).await)
    }
    .await;

    if !settings.keep {
        for name in sandboxes.all() {
            openshell::forward_stop_all(name).await;
            openshell::delete(name).await;
        }
        surreal.stop().await;
    }
    for server in servers {
        server.abort();
    }
    outcome
}

async fn setup(
    settings: &Settings,
    workdir: &Path,
    ports: HostPorts,
    sandboxes: &Sandboxes,
    surreal: &Surreal,
) -> anyhow::Result<RunContext> {
    let server_policy = workdir.join("server.yaml");
    let client_policy = workdir.join("client.yaml");
    let dev_policy = workdir.join("dev.yaml");
    policy::write(&policy::server(), &server_policy)?;
    policy::write(&policy::client(&ports), &client_policy)?;
    policy::write(&policy::dev(), &dev_policy)?;

    let grpc_forward_port = host::free_port()?;
    let redap_forward_port = host::free_port()?;
    let home = || ("HOME".to_owned(), "/sandbox".to_owned());
    let spec = |name: &str, policy: &Path, command: Vec<String>| SandboxSpec {
        name: name.to_owned(),
        image: settings.image.clone(),
        policy: policy.to_path_buf(),
        env: vec![home()],
        expose: None,
        restart_on_failure: true,
        gpu: false,
        providers: Vec::new(),
        command,
    };
    let sleep = || vec!["sleep".to_owned(), "infinity".to_owned()];

    let mut server = spec(
        &sandboxes.server,
        &server_policy,
        [
            "probe",
            "serve",
            "--http",
            &format!("127.0.0.1:{SERVER_HTTP}"),
            "--grpc",
            &format!("127.0.0.1:{grpc_forward_port}"),
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    server.expose = Some(Exposure {
        port: SERVER_HTTP,
        service: None,
        bearer_passthrough: true,
    });
    openshell::create(&server)
        .await
        .context("create server sandbox")?;
    openshell::expose(&sandboxes.server, grpc_forward_port, "grpc", true).await?;

    let mut client = spec(&sandboxes.client, &client_policy, sleep());
    client
        .env
        .push(("PROBE_SURREAL_USER".into(), "root".into()));
    client
        .env
        .push(("PROBE_SURREAL_PASS".into(), surreal.password.clone()));
    openshell::create(&client)
        .await
        .context("create client sandbox")?;

    let mut redap = spec(
        &sandboxes.redap,
        &server_policy,
        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "mkdir -p /sandbox/data && /usr/local/rerun/bin/python /usr/local/share/probe/make_rrd.py /sandbox/data/segment.rrd \
                 && exec /usr/local/rerun/bin/rerun server --host 127.0.0.1 -p {redap_forward_port} -d probe=/sandbox/data"
            ),
        ],
    );
    redap.env.push(("RERUN_ANALYTICS".into(), "false".into()));
    redap.expose = Some(Exposure {
        port: redap_forward_port,
        service: None,
        bearer_passthrough: false,
    });
    openshell::create(&redap)
        .await
        .context("create Redap sandbox")?;

    let mut dev = spec(&sandboxes.dev, &dev_policy, sleep());
    dev.env
        .push(("CARGO_TARGET_DIR".into(), "/sandbox/target".into()));
    openshell::create(&dev)
        .await
        .context("create dev sandbox")?;

    if let Some(name) = &sandboxes.gpu {
        let mut gpu = spec(name, &server_policy, sleep());
        gpu.gpu = true;
        openshell::create(&gpu)
            .await
            .context("create GPU sandbox")?;
    }

    let server_url = openshell::service_url(&sandboxes.server, None).await?;
    let server_grpc_url = openshell::service_url(&sandboxes.server, Some("grpc")).await?;
    let redap_url = openshell::service_url(&sandboxes.redap, None).await?;
    wait_http_ok(&format!("{server_url}/healthz")).await?;
    openshell::forward_start(grpc_forward_port, &sandboxes.server).await?;
    openshell::forward_start(redap_forward_port, &sandboxes.redap).await?;
    wait_listening(grpc_forward_port).await?;
    wait_listening(redap_forward_port).await?;
    wait_redap_ready(&sandboxes.redap, redap_forward_port).await?;

    Ok(RunContext {
        policies: workdir.to_path_buf(),
        sandboxes: Sandboxes {
            server: sandboxes.server.clone(),
            client: sandboxes.client.clone(),
            redap: sandboxes.redap.clone(),
            dev: sandboxes.dev.clone(),
            gpu: sandboxes.gpu.clone(),
        },
        ports,
        server_url,
        server_grpc_url,
        grpc_forward_port,
        redap_url,
        redap_forward_port,
    })
}

async fn wait_http_ok(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..120 {
        if client
            .get(url)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("{url} did not answer within 60 seconds")
}

async fn wait_listening(port: u16) -> anyhow::Result<()> {
    for _ in 0..120 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("forward on port {port} did not listen within 60 seconds")
}

async fn wait_redap_ready(sandbox: &str, port: u16) -> anyhow::Result<()> {
    let check = format!("grep -qi ':{port:04X} ' /proc/net/tcp");
    for _ in 0..240 {
        if openshell::exec(sandbox, &["sh", "-c", &check])
            .await
            .is_ok_and(|o| o.success)
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("Rerun server in {sandbox} did not listen within two minutes")
}

fn progress(started: std::time::Instant, group: &str, outcomes: &[Outcome]) {
    for outcome in outcomes {
        let status = serde_json::to_value(outcome.status).unwrap_or_default();
        eprintln!(
            "[{:>5}s] {group:<10} {:<12} {}",
            started.elapsed().as_secs(),
            status.as_str().unwrap_or(""),
            outcome.id
        );
    }
}

async fn scenarios(settings: &Settings, _workdir: &Path, context: &RunContext) -> Vec<Outcome> {
    let started = std::time::Instant::now();
    let mut outcomes = Vec::new();
    let mut record = |group: &str, batch: Vec<Outcome>| {
        progress(started, group, &batch);
        outcomes.extend(batch);
    };
    record("exposure", exposure(settings, context).await);
    record("outbound", outbound(settings, context).await);
    record("redap", redap(settings, context).await);
    record("transfer", transfer(settings, context).await);
    record("dev", development(settings, context).await);
    record("gpu", vec![gpu(context).await]);
    record("git", vec![git::provider_push(settings, context).await]);
    record("peer", peer::run(settings, context).await);
    record(
        "provider",
        vec![provider::bound_secret(settings, context).await],
    );
    // Last, because a failure here can leave a sandbox record that no API can remove.
    record("lifecycle", vec![fast_failure(settings, context).await]);
    outcomes
}

async fn exposure(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let limit = deadline(settings);
    let base = &context.server_url;
    let seconds = settings.stream_seconds;
    let mut outcomes = Vec::new();

    const HTTP_RULE: &str = "exposed HTTP answers health, MCP POST and form tokens, passes one Bearer header and refuses Basic";
    outcomes.push(
        match within(limit, client::http(base, "probe-bearer-token")).await {
            Ok(r) => Outcome::check(
                "exposure.http",
                HTTP_RULE,
                [
                    "/healthz/status",
                    "/mcp_post/status",
                    "/form_token/status",
                    "/bearer_auth/status",
                ]
                .iter()
                .all(|p| num(&r, p) == Some(200))
                    && num(&r, "/bearer_auth/body/authorization/bearer_len") == Some(18)
                    && num(&r, "/basic_auth/status") == Some(400)
                    && r.pointer("/body_8mib/content_matches") == Some(&json!(true)),
                r,
            ),
            Err(e) => Outcome::error("exposure.http", HTTP_RULE, e),
        },
    );

    let ws_url = base
        .replacen("http://", "ws://", 1)
        .replacen("https://", "wss://", 1)
        + "/ws";
    const WS_RULE: &str = "an exposed WebSocket upgrades and echoes every message";
    outcomes.push(
        match within(limit, client::ws(&ws_url, seconds, STREAM_INTERVAL_MS)).await {
            Ok(r) => Outcome::check(
                "exposure.websocket",
                WS_RULE,
                num(&r, "/upgrade_status") == Some(101)
                    && num(&r, "/echoed") == num(&r, "/expected"),
                r,
            ),
            Err(e) => Outcome::error("exposure.websocket", WS_RULE, e),
        },
    );

    const SSE_RULE: &str = "ten exposed SSE streams deliver every event without buffering";
    outcomes.push(
        match within(limit, client::sse(base, seconds, STREAM_INTERVAL_MS, 10)).await {
            Ok(r) => Outcome::check(
                "exposure.sse",
                SSE_RULE,
                num(&r, "/complete_streams") == Some(10)
                    && num(&r, "/worst_max_gap_ms").is_some_and(|g| g <= STREAM_INTERVAL_MS + 500),
                r,
            ),
            Err(e) => Outcome::error("exposure.sse", SSE_RULE, e),
        },
    );

    const FRAMES_RULE: &str =
        "an exposed length-framed binary stream delivers every frame without buffering";
    outcomes.push(
        match within(limit, client::frames(base, seconds, 100, 65536)).await {
            Ok(r) => Outcome::check("exposure.frames", FRAMES_RULE, streamed_cleanly(&r, 100), r),
            Err(e) => Outcome::error("exposure.frames", FRAMES_RULE, e),
        },
    );

    const BURST_RULE: &str = "fifty simultaneous exposed SSE opens either stream completely or are refused with 502 at setup";
    outcomes.push(match within(limit, client::sse(base, 5, STREAM_INTERVAL_MS, BURST_STREAMS)).await {
        Ok(r) => {
            let errors: Vec<String> = r["errors"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
            Outcome::check(
                "exposure.burst",
                BURST_RULE,
                errors.iter().all(|e| e.contains("502")),
                json!({"complete_streams": r["complete_streams"], "refused": errors.len(), "report": r}),
            )
        }
        Err(e) => Outcome::error("exposure.burst", BURST_RULE, e),
    });

    const NATIVE_GRPC_RULE: &str =
        "limit: exposure relays HTTP/1.1, so native gRPC through exposure fails";
    outcomes.push(
        match within(
            limit,
            crate::grpc::client(&context.server_grpc_url, 3, STREAM_INTERVAL_MS),
        )
        .await
        {
            Ok(r) => {
                let failed = !r["chat_error"].is_null() || num(&r, "/chat_rtt_ms/count") == Some(0);
                Outcome::limit("exposure.grpc_native", NATIVE_GRPC_RULE, failed, r)
            }
            Err(e) => Outcome::limit(
                "exposure.grpc_native",
                NATIVE_GRPC_RULE,
                true,
                json!({"error": format!("{e:#}")}),
            ),
        },
    );

    const FORWARD_RULE: &str = "native gRPC through a port forward streams in both directions";
    let forward_url = format!("http://127.0.0.1:{}", context.grpc_forward_port);
    outcomes.push(
        match within(
            limit,
            crate::grpc::client(&forward_url, seconds, STREAM_INTERVAL_MS),
        )
        .await
        {
            Ok(r) => Outcome::check(
                "forward.grpc",
                FORWARD_RULE,
                r["chat_error"].is_null()
                    && r["ticks_error"].is_null()
                    && num(&r, "/chat_rtt_ms/count") == num(&r, "/expected"),
                r,
            ),
            Err(e) => Outcome::error("forward.grpc", FORWARD_RULE, e),
        },
    );
    outcomes
}

async fn outbound(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let sandbox = &context.sandboxes.client;
    let host = policy::HOST;
    let ports = &context.ports;
    let seconds = settings.stream_seconds.to_string();
    let interval = STREAM_INTERVAL_MS.to_string();
    let plain = format!("http://{host}:{}", ports.plain_http);
    let mut outcomes = Vec::new();

    let limit = deadline(settings);
    let probe = |args: Vec<String>| async move {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        within(limit, openshell::exec_probe(sandbox, &refs)).await
    };
    let args = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();

    const HTTP_RULE: &str = "a sandbox reaches an uninspected HTTP endpoint on the gateway host";
    outcomes.push(match probe(args(&["http", "--base", &plain])).await {
        Ok(r) => Outcome::check(
            "outbound.http",
            HTTP_RULE,
            [
                "/healthz/status",
                "/mcp_post/status",
                "/form_token/status",
                "/bearer_auth/status",
                "/basic_auth/status",
            ]
            .iter()
            .all(|p| num(&r, p) == Some(200))
                && r.pointer("/body_8mib/content_matches") == Some(&json!(true)),
            r,
        ),
        Err(e) => Outcome::error("outbound.http", HTTP_RULE, e),
    });

    const SSE_RULE: &str = "ten outbound SSE streams deliver every event without buffering";
    outcomes.push(
        match probe(args(&[
            "sse",
            "--base",
            &plain,
            "--seconds",
            &seconds,
            "--interval-ms",
            &interval,
            "--streams",
            "10",
        ]))
        .await
        {
            Ok(r) => Outcome::check(
                "outbound.sse",
                SSE_RULE,
                num(&r, "/complete_streams") == Some(10)
                    && num(&r, "/worst_max_gap_ms").is_some_and(|g| g <= STREAM_INTERVAL_MS + 500),
                r,
            ),
            Err(e) => Outcome::error("outbound.sse", SSE_RULE, e),
        },
    );

    const FRAMES_RULE: &str = "an outbound length-framed binary stream delivers every frame";
    outcomes.push(
        match probe(args(&[
            "frames",
            "--base",
            &plain,
            "--seconds",
            &seconds,
            "--interval-ms",
            "100",
        ]))
        .await
        {
            Ok(r) => Outcome::check("outbound.frames", FRAMES_RULE, streamed_cleanly(&r, 100), r),
            Err(e) => Outcome::error("outbound.frames", FRAMES_RULE, e),
        },
    );

    const WS_RULE: &str = "an outbound WebSocket to an uninspected endpoint echoes every message";
    let ws = format!("ws://{host}:{}/ws", ports.plain_http);
    outcomes.push(
        match probe(args(&[
            "ws",
            "--url",
            &ws,
            "--seconds",
            &seconds,
            "--interval-ms",
            &interval,
        ]))
        .await
        {
            Ok(r) => Outcome::check(
                "outbound.websocket",
                WS_RULE,
                num(&r, "/upgrade_status") == Some(101)
                    && num(&r, "/echoed") == num(&r, "/expected"),
                r,
            ),
            Err(e) => Outcome::error("outbound.websocket", WS_RULE, e),
        },
    );

    let grpc_rule =
        |id: &'static str, rule: &'static str, report: anyhow::Result<Value>| match report {
            Ok(r) => Outcome::check(
                id,
                rule,
                r["chat_error"].is_null()
                    && r["ticks_error"].is_null()
                    && num(&r, "/chat_rtt_ms/count") == num(&r, "/expected"),
                r,
            ),
            Err(e) => Outcome::error(id, rule, e),
        };
    let grpc_plain = format!("http://{host}:{}", ports.plain_grpc);
    outcomes.push(grpc_rule(
        "outbound.grpc",
        "outbound native gRPC streams in both directions on an uninspected endpoint",
        probe(args(&[
            "grpc",
            "--url",
            &grpc_plain,
            "--seconds",
            &seconds,
            "--interval-ms",
            &interval,
        ]))
        .await,
    ));
    let grpc_tcp = format!("http://{host}:{}", ports.tcp_grpc);
    outcomes.push(grpc_rule(
        "outbound.grpc_tcp",
        "outbound native gRPC streams in both directions on a tcp endpoint",
        probe(args(&[
            "grpc",
            "--url",
            &grpc_tcp,
            "--seconds",
            &seconds,
            "--interval-ms",
            &interval,
        ]))
        .await,
    ));

    const MCP_RULE: &str = "MCP 2026-07-28 inspection allows tools/list, server/discover and an allowed tool, denies a denied tool and rejects a missing Mcp-Method header";
    let mcp = format!("http://{host}:{}", ports.mcp_http);
    outcomes.push(
        match probe(args(&[
            "mcp-policy",
            "--base",
            &mcp,
            "--denied-tool",
            policy::DENIED_TOOL,
        ]))
        .await
        {
            Ok(r) => Outcome::check(
                "outbound.mcp_policy",
                MCP_RULE,
                num(&r, "/tools_list") == Some(200)
                    && num(&r, "/server_discover") == Some(200)
                    && num(&r, "/allowed_tool") == Some(200)
                    && num(&r, "/denied_tool") == Some(403)
                    && num(&r, "/missing_method_header") == Some(400),
                r,
            ),
            Err(e) => Outcome::error("outbound.mcp_policy", MCP_RULE, e),
        },
    );

    const MCP_UPGRADE_RULE: &str =
        "limit: endpoints inspected as MCP refuse WebSocket upgrades with 403";
    let mcp_ws = format!("ws://{host}:{}/ws", ports.mcp_http);
    outcomes.push(
        match probe(args(&[
            "ws",
            "--url",
            &mcp_ws,
            "--seconds",
            "2",
            "--interval-ms",
            &interval,
        ]))
        .await
        {
            Ok(r) => Outcome::limit(
                "outbound.mcp_upgrade",
                MCP_UPGRADE_RULE,
                text(&r, "/connect_error").contains("403"),
                r,
            ),
            Err(e) => Outcome::error("outbound.mcp_upgrade", MCP_UPGRADE_RULE, e),
        },
    );

    const WS_ENDPOINT_RULE: &str = "an endpoint inspected as websocket upgrades and echoes";
    let ws_inspected = format!("ws://{host}:{}/ws", ports.websocket_http);
    outcomes.push(
        match probe(args(&[
            "ws",
            "--url",
            &ws_inspected,
            "--seconds",
            &seconds,
            "--interval-ms",
            &interval,
        ]))
        .await
        {
            Ok(r) => Outcome::check(
                "outbound.websocket_inspected",
                WS_ENDPOINT_RULE,
                num(&r, "/upgrade_status") == Some(101)
                    && num(&r, "/echoed") == num(&r, "/expected"),
                r,
            ),
            Err(e) => Outcome::error("outbound.websocket_inspected", WS_ENDPOINT_RULE, e),
        },
    );

    const HTTPS_RULE: &str = "a rustls HTTPS client trusts the TLS-inspecting proxy";
    outcomes.push(
        match probe(args(&[
            "https",
            "--url",
            "https://index.crates.io/config.json",
        ]))
        .await
        {
            Ok(r) => Outcome::check(
                "outbound.https_rustls",
                HTTPS_RULE,
                num(&r, "/outcome/status") == Some(200),
                r,
            ),
            Err(e) => Outcome::error("outbound.https_rustls", HTTPS_RULE, e),
        },
    );

    for (id, port, rule) in [
        (
            "surreal.inspected",
            ports.surreal_inspected,
            "SurrealDB queries and LIVE notifications work on an uninspected endpoint",
        ),
        (
            "surreal.tcp",
            ports.surreal_tcp,
            "SurrealDB queries and LIVE notifications work on a tcp endpoint",
        ),
    ] {
        let address = format!("{host}:{port}");
        outcomes.push(
            match probe(args(&[
                "surreal",
                "--address",
                &address,
                "--seconds",
                &seconds,
                "--interval-ms",
                &interval,
            ]))
            .await
            {
                Ok(r) => Outcome::check(
                    id,
                    rule,
                    num(&r, "/notified") == num(&r, "/expected")
                        && num(&r, "/write_errors") == Some(0)
                        && r["error"].is_null(),
                    r,
                ),
                Err(e) => Outcome::error(id, rule, e),
            },
        );
    }
    outcomes
}

async fn redap(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let limit = deadline(settings);
    let mut outcomes = Vec::new();
    const FORWARD_RULE: &str =
        "the Rerun 0.38.1 Catalog SDK lists and reads a dataset through a port forward";
    let forward = format!("rerun+http://127.0.0.1:{}", context.redap_forward_port);
    outcomes.push(
        match within(limit, host::catalog_probe(&settings.image, &forward)).await {
            Ok(r) => Outcome::check(
                "redap.forward",
                FORWARD_RULE,
                r["ok"] == json!(true) && num(&r, "/rows") == Some(SAMPLE_ROWS),
                r,
            ),
            Err(e) => Outcome::error("redap.forward", FORWARD_RULE, e),
        },
    );

    const EXPOSURE_RULE: &str = "limit: native Redap clients cannot connect through exposure";
    let exposed = format!("rerun+{}", context.redap_url);
    outcomes.push(
        match within(limit, host::catalog_probe(&settings.image, &exposed)).await {
            Ok(r) => Outcome::limit(
                "redap.native_exposure",
                EXPOSURE_RULE,
                r["ok"] != json!(true),
                r,
            ),
            Err(e) => Outcome::error("redap.native_exposure", EXPOSURE_RULE, e),
        },
    );

    const GRPC_WEB_RULE: &str = "Redap gRPC-Web, used by the WebViewer, answers through exposure";
    outcomes.push(
        match probes::grpc_web(
            &context.redap_url,
            "/rerun.cloud.v1alpha1.RerunCloudService/Version",
        )
        .await
        {
            Ok(r) => Outcome::check(
                "redap.grpc_web",
                GRPC_WEB_RULE,
                num(&r, "/status") == Some(200) && r["grpc_status_ok"] == json!(true),
                r,
            ),
            Err(e) => Outcome::error("redap.grpc_web", GRPC_WEB_RULE, e),
        },
    );
    outcomes
}

async fn transfer(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let limit = 900;
    let bytes = settings.transfer_mib * 1024 * 1024;
    let mut outcomes = Vec::new();
    const OUT_RULE: &str = "a sandbox downloads a large body from the gateway host byte-exact";
    let plain = format!("http://{}:{}", policy::HOST, context.ports.plain_http);
    let bytes_text = bytes.to_string();
    outcomes.push(
        match openshell::exec_probe(
            &context.sandboxes.client,
            &["big", "--base", &plain, "--bytes", &bytes_text],
        )
        .await
        {
            Ok(r) => Outcome::check(
                "transfer.outbound",
                OUT_RULE,
                r["content_matches"] == json!(true),
                r,
            ),
            Err(e) => Outcome::error("transfer.outbound", OUT_RULE, e),
        },
    );
    const IN_RULE: &str =
        "the host downloads a large body from an exposed sandbox service byte-exact";
    outcomes.push(
        match within(limit, client::big(&context.server_url, bytes)).await {
            Ok(r) => Outcome::check(
                "transfer.inbound",
                IN_RULE,
                r["content_matches"] == json!(true),
                r,
            ),
            Err(e) => Outcome::error("transfer.inbound", IN_RULE, e),
        },
    );
    outcomes
}

async fn shell(sandbox: &str, script: &str) -> (bool, String) {
    match within(900, openshell::exec(sandbox, &["bash", "-lc", script])).await {
        Ok(o) => (
            o.success,
            format!("{}{}", o.stdout, o.stderr)
                .chars()
                .rev()
                .take(600)
                .collect::<String>()
                .chars()
                .rev()
                .collect(),
        ),
        Err(e) => (false, format!("{e:#}")),
    }
}

async fn development(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let dev = &context.sandboxes.dev;
    let mut outcomes = Vec::new();

    const INSTALL_RULE: &str = "inside a sandbox, rustup adds a target, cargo installs a crate, Git fetches from GitHub and a Cargo Git dependency builds";
    let steps = [
        ("rustup_target", "rustup target add wasm32-unknown-unknown"),
        (
            "cargo_install",
            "cargo install -q --locked cargo-machete && command -v cargo-machete",
        ),
        (
            "git_fetch",
            "git ls-remote https://github.com/NVIDIA/OpenShell HEAD",
        ),
        (
            "cargo_git_dependency",
            "rm -rf /sandbox/gitdep && mkdir -p /sandbox/gitdep/src && cd /sandbox/gitdep \
             && printf '[package]\\nname = \"gitdep\"\\nversion = \"0.0.0\"\\nedition = \"2024\"\\n[dependencies]\\nitoa = { git = \"https://github.com/dtolnay/itoa\", tag = \"1.0.15\" }\\n' > Cargo.toml \
             && printf 'fn main() { println!(\"{}\", itoa::Buffer::new().format(42)); }\\n' > src/main.rs && cargo run -q",
        ),
    ];
    let mut details = serde_json::Map::new();
    let mut all_ok = true;
    for (name, script) in steps {
        let started = std::time::Instant::now();
        let (ok, output) = shell(dev, script).await;
        all_ok &= ok;
        details.insert(
            name.into(),
            json!({"ok": ok, "seconds": started.elapsed().as_secs_f64(), "output_tail": output}),
        );
    }
    outcomes.push(Outcome::check(
        "dev.installable",
        INSTALL_RULE,
        all_ok,
        Value::Object(details),
    ));

    const PERSIST_RULE: &str = "the workspace keeps a verified cache and Cargo output across stop, start and restart-policy replacement";
    let prepare = format!(
        "cp -r /usr/local/share/probe/sample /sandbox/sample && cd /sandbox/sample && cargo build -q --release \
         && dd if=/dev/urandom of=/sandbox/cache.bin bs=1M count={} status=none && sha256sum /sandbox/cache.bin > /sandbox/cache.sha256",
        settings.cache_mib
    );
    let verify = "cd /sandbox && sha256sum -c --quiet cache.sha256 && test -x /sandbox/target/release/probe-sample";
    let mut details = serde_json::Map::new();
    let (prepared, output) = shell(dev, &prepare).await;
    details.insert(
        "prepare".into(),
        json!({"ok": prepared, "output_tail": output}),
    );
    let stop_start = async {
        openshell::stop(dev).await?;
        openshell::start(dev).await
    }
    .await;
    let (after_start, _) = shell(dev, verify).await;
    details.insert("after_stop_start".into(), json!({"ok": stop_start.is_ok() && after_start, "error": stop_start.err().map(|e| format!("{e:#}"))}));
    let _ = shell(dev, "pkill -KILL -x sleep").await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    let ready = openshell::wait_ready(dev, Duration::from_secs(180)).await;
    let restarts = openshell::get(dev)
        .await
        .ok()
        .and_then(|v| v.get("restart_count").and_then(Value::as_u64));
    let (after_restart, _) = shell(dev, verify).await;
    details.insert(
        "after_restart".into(),
        json!({"ok": ready.is_ok() && after_restart, "restart_count": restarts}),
    );
    outcomes.push(Outcome::check(
        "dev.persistence",
        PERSIST_RULE,
        prepared && after_start && after_restart && restarts.is_some_and(|n| n >= 1),
        Value::Object(details),
    ));
    outcomes
}

async fn gpu(context: &RunContext) -> Outcome {
    const RULE: &str = "a GPU sandbox sees the NVIDIA device";
    let Some(name) = &context.sandboxes.gpu else {
        return Outcome::skip(
            "gpu.device",
            RULE,
            "this host has no NVIDIA GPU for sandboxes",
        );
    };
    let (ok, output) = shell(
        name,
        "nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader",
    )
    .await;
    Outcome::check(
        "gpu.device",
        RULE,
        ok && !output.trim().is_empty(),
        json!({"output": output.trim()}),
    )
}

async fn fast_failure(settings: &Settings, context: &RunContext) -> Outcome {
    const RULE: &str = "a main process that exits at once under the on-failure restart policy keeps restarting or reports Error, and the sandbox deletes";
    if !settings.lifecycle {
        return Outcome::skip(
            "lifecycle.fast_failure",
            RULE,
            "run with --lifecycle; on OpenShell 0.1.3 this scenario can leave a record that no API deletes",
        );
    }
    let name = format!("q{}-crash", settings.run_id);
    let policy = context.policies.join("server.yaml");
    if let Err(error) = openshell::submit(&name, &settings.image, &policy, &["false"]).await {
        return Outcome::error("lifecycle.fast_failure", RULE, error);
    }
    tokio::time::sleep(Duration::from_secs(45)).await;
    let observed = openshell::get(&name).await.ok();
    let phase = observed
        .as_ref()
        .and_then(|v| v["phase"].as_str().map(str::to_owned))
        .unwrap_or_default();
    let restarts = observed
        .as_ref()
        .and_then(|v| v["restart_count"].as_u64())
        .unwrap_or(0);
    let condition = observed
        .as_ref()
        .and_then(|v| {
            v["conditions"]
                .get(0)
                .and_then(|c| c["message"].as_str().map(str::to_owned))
        })
        .unwrap_or_default();
    let pending = observed
        .as_ref()
        .and_then(|v| v.pointer("/provisioning/driver_operation_pending").cloned());
    let (deleted, delete_message) =
        openshell::delete_and_confirm(&name, Duration::from_secs(90)).await;
    let progressed = restarts >= 2 || phase == "Error";
    Outcome::check(
        "lifecycle.fast_failure",
        RULE,
        progressed && deleted,
        json!({
            "phase_after_45s": phase,
            "restart_count": restarts,
            "condition": condition,
            "driver_operation_pending": pending,
            "deleted_within_90s": deleted,
            "delete_response": delete_message,
            "cleanup_if_stuck": "if the record stays, remove its containers with docker rm -f and reset the gateway database; no OpenShell 0.1.3 API resolves a lost driver operation",
        }),
    )
}
