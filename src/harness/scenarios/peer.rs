//! One sandbox reaching another sandbox's service, which registration between
//! component environments needs, and the loopback behavior found while porting.

use super::{RunContext, Settings, deadline, num, shell, wait_http_ok, wait_listening, within};
use crate::harness::{
    host,
    openshell::{self, Exposure, SandboxSpec},
    policy,
    report::Outcome,
};
use anyhow::{Context, anyhow};
use serde_json::{Value, json};

const EXPOSURE_ID: &str = "peer.exposure";
const EXPOSURE_RULE: &str = "limit: a sandbox cannot reach another sandbox's exposed service, because the exposure name resolves to its own loopback and requests to host.openshell.internal must carry that authority";
const FORWARD_ID: &str = "peer.forward";
const FORWARD_RULE: &str = "a sandbox reaches another sandbox's service through a port forward on the gateway host, with MCP POST, bearer passthrough and SSE streams intact";
const LOOPBACK_ID: &str = "sandbox.loopback_close";
const LOOPBACK_RULE: &str = "limit: inside a sandbox a closed loopback listener keeps completing TCP handshakes, while a port that never listened refuses";

pub async fn run(settings: &Settings, context: &RunContext) -> Vec<Outcome> {
    let server = format!("vv-qual-{}-peer", settings.run_id);
    let client = format!("vv-qual-{}-peerc", settings.run_id);
    let outcomes = match scenarios(settings, context, &server, &client).await {
        Ok(outcomes) => outcomes,
        Err(error) => {
            let message = format!("{error:#}");
            vec![
                Outcome::error(EXPOSURE_ID, EXPOSURE_RULE, anyhow!("{message}")),
                Outcome::error(FORWARD_ID, FORWARD_RULE, anyhow!("{message}")),
                Outcome::error(LOOPBACK_ID, LOOPBACK_RULE, anyhow!("{message}")),
            ]
        }
    };
    if !settings.keep {
        openshell::forward_stop_all(&server).await;
        openshell::delete(&server).await;
        openshell::delete(&client).await;
    }
    outcomes
}

async fn scenarios(
    settings: &Settings,
    context: &RunContext,
    server: &str,
    client: &str,
) -> anyhow::Result<Vec<Outcome>> {
    let port = host::free_port()?;
    let grpc = host::free_port()?;
    let spec = |name: &str, policy: std::path::PathBuf, command: Vec<String>| SandboxSpec {
        name: name.to_owned(),
        image: settings.image.clone(),
        policy,
        env: vec![("HOME".into(), "/sandbox".into())],
        expose: None,
        restart_on_failure: false,
        gpu: false,
        providers: Vec::new(),
        command,
    };

    let mut peer = spec(
        server,
        context.policies.join("server.yaml"),
        [
            "probe",
            "serve",
            "--http",
            &format!("127.0.0.1:{port}"),
            "--grpc",
            &format!("127.0.0.1:{grpc}"),
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    peer.expose = Some(Exposure {
        port,
        service: None,
        bearer_passthrough: true,
    });
    openshell::create(&peer)
        .await
        .context("create peer sandbox")?;
    let exposure_url = openshell::service_url(server, None).await?;
    wait_http_ok(&format!("{exposure_url}/healthz")).await?;
    let parsed = reqwest::Url::parse(&exposure_url)?;
    let exposure_host = parsed.host_str().context("exposure host")?.to_owned();
    let gateway_port = parsed.port_or_known_default().context("exposure port")?;
    openshell::forward_start(port, server).await?;
    wait_listening(port).await?;

    let client_policy = context.policies.join("peer-client.yaml");
    policy::write(
        &policy::peer_client(&exposure_host, gateway_port, port),
        &client_policy,
    )?;
    openshell::create(&spec(
        client,
        client_policy,
        vec!["sleep".into(), "infinity".into()],
    ))
    .await
    .context("create peer client sandbox")?;

    Ok(vec![
        exposure(
            settings,
            client,
            &exposure_url,
            &exposure_host,
            gateway_port,
        )
        .await,
        forward(settings, client, port).await,
        loopback(client).await,
    ])
}

async fn exposure(
    settings: &Settings,
    client: &str,
    exposure_url: &str,
    exposure_host: &str,
    gateway_port: u16,
) -> Outcome {
    let direct = within(
        deadline(settings),
        openshell::exec_probe(client, &["http", "--base", exposure_url]),
    )
    .await
    .unwrap_or_else(|error| json!({"error": format!("{error:#}")}));
    let reached_directly = num(&direct, "/healthz/status") == Some(200);
    let (_, override_status) = shell(
        client,
        &format!(
            "curl -s -m 10 -o /dev/null -w '%{{http_code}}' -H 'Host: {exposure_host}' http://{}:{gateway_port}/healthz",
            policy::HOST
        ),
    )
    .await;
    let override_status = override_status.trim().to_owned();
    Outcome::limit(
        EXPOSURE_ID,
        EXPOSURE_RULE,
        !(reached_directly || override_status == "200"),
        json!({
            "exposureUrl": exposure_url,
            "direct": {"healthz": direct.get("healthz"), "mcpPost": direct.get("mcpPost")},
            "gatewayListenerWithPeerAuthority": {"status": override_status},
        }),
    )
}

async fn forward(settings: &Settings, client: &str, port: u16) -> Outcome {
    let base = format!("http://{}:{port}", policy::HOST);
    let limit = deadline(settings);
    let http = within(
        limit,
        openshell::exec_probe(client, &["http", "--base", &base]),
    )
    .await;
    let seconds = settings.stream_seconds.to_string();
    let sse = within(
        limit,
        openshell::exec_probe(
            client,
            &[
                "sse",
                "--base",
                &base,
                "--seconds",
                &seconds,
                "--interval-ms",
                "500",
                "--streams",
                "3",
            ],
        ),
    )
    .await;
    let (http, sse) = match (http, sse) {
        (Ok(http), Ok(sse)) => (http, sse),
        (Err(error), _) | (_, Err(error)) => {
            return Outcome::error(FORWARD_ID, FORWARD_RULE, error);
        }
    };
    let http_ok = ["/healthz/status", "/mcpPost/status", "/bearerAuth/status"]
        .iter()
        .all(|pointer| num(&http, pointer) == Some(200))
        && http.pointer("/body8mib/contentMatches") == Some(&json!(true));
    let sse_ok = num(&sse, "/completeStreams") == Some(3)
        && num(&sse, "/worstMaxGapMs").is_some_and(|gap| gap <= 1000);
    Outcome::check(
        FORWARD_ID,
        FORWARD_RULE,
        http_ok && sse_ok,
        json!({"base": base, "http": http, "sse": sse}),
    )
}

const LOOPBACK_SCRIPT: &str = r#"python3 - <<'PY'
import json, socket, time

def connect(port):
    try:
        socket.create_connection(("127.0.0.1", port), timeout=3).close()
        return "succeeded"
    except OSError as error:
        return type(error).__name__

used = socket.socket()
used.bind(("127.0.0.1", 0))
used.listen(8)
used_port = used.getsockname()[1]
client = socket.create_connection(("127.0.0.1", used_port))
accepted, _ = used.accept()
for sock in (accepted, client, used):
    sock.close()
time.sleep(0.5)

never = socket.socket()
never.bind(("127.0.0.1", 0))
never_port = never.getsockname()[1]
never.close()
print(json.dumps({"closedListener": connect(used_port), "neverListened": connect(never_port)}))
PY"#;

async fn loopback(client: &str) -> Outcome {
    let (ok, output) = shell(client, LOOPBACK_SCRIPT).await;
    let report: Value = output
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str(line).ok())
        .unwrap_or_else(|| json!({"outputTail": output}));
    if !ok || report.get("closedListener").is_none() {
        return Outcome::error(
            LOOPBACK_ID,
            LOOPBACK_RULE,
            anyhow!("loopback probe failed: {report}"),
        );
    }
    Outcome::limit(
        LOOPBACK_ID,
        LOOPBACK_RULE,
        report["closedListener"] == "succeeded",
        report,
    )
}
