//! Thin wrapper over the `openshell` CLI, the supported interface for a local gateway.

use anyhow::{Context, bail};
use serde_json::Value;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::process::Command;

pub struct Exposure {
    pub port: u16,
    pub service: Option<String>,
    pub bearer_passthrough: bool,
}

pub struct SandboxSpec {
    pub name: String,
    pub image: String,
    pub policy: PathBuf,
    pub env: Vec<(String, String)>,
    pub expose: Option<Exposure>,
    pub restart_on_failure: bool,
    pub gpu: bool,
    pub command: Vec<String>,
}

pub struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

async fn run(args: &[&str]) -> anyhow::Result<Output> {
    // NO_COLOR keeps output plain without adding a flag that would land after `--`.
    let output = Command::new("openshell")
        .args(args)
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
        .context("run openshell")?;
    Ok(Output {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

async fn run_ok(args: &[&str]) -> anyhow::Result<Output> {
    let output = run(args).await?;
    if !output.success {
        bail!(
            "openshell {} failed: {}",
            args.join(" "),
            output.stderr.trim()
        );
    }
    Ok(output)
}

pub async fn version() -> anyhow::Result<String> {
    let output = run_ok(&["--version"]).await?;
    Ok(output
        .stdout
        .trim()
        .trim_start_matches("openshell ")
        .to_owned())
}

pub async fn compute_driver() -> anyhow::Result<String> {
    let output = run_ok(&["gateway", "info"]).await?;
    let mut lines = output
        .stdout
        .lines()
        .skip_while(|l| !l.contains("Compute drivers:"));
    lines.next();
    Ok(lines.next().unwrap_or_default().trim().to_owned())
}

pub async fn create(spec: &SandboxSpec) -> anyhow::Result<()> {
    let policy = spec.policy.to_string_lossy().into_owned();
    let mut args: Vec<String> = [
        "sandbox",
        "create",
        "--name",
        &spec.name,
        "--from",
        &spec.image,
        "--policy",
        &policy,
        "--detach",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (key, value) in &spec.env {
        args.push("--env".into());
        args.push(format!("{key}={value}"));
    }
    if let Some(exposure) = &spec.expose {
        args.push("--expose".into());
        args.push(exposure.port.to_string());
        if exposure.bearer_passthrough {
            args.push("--expose-authorization-mode".into());
            args.push("bearer-passthrough".into());
        }
    }
    if spec.restart_on_failure {
        args.push("--restart-policy".into());
        args.push("on-failure".into());
    }
    if spec.gpu {
        args.push("--gpu".into());
    }
    args.push("--".into());
    args.extend(spec.command.iter().cloned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_ok(&refs).await?;
    wait_ready(&spec.name, Duration::from_secs(180)).await
}

/// Submits a sandbox without waiting for it to become Ready.
pub async fn submit(
    name: &str,
    image: &str,
    policy: &std::path::Path,
    command: &[&str],
) -> anyhow::Result<()> {
    let policy = policy.to_string_lossy();
    let mut args = vec![
        "sandbox",
        "create",
        "--name",
        name,
        "--from",
        image,
        "--policy",
        &policy,
        "--restart-policy",
        "on-failure",
        "--detach",
        "--",
    ];
    args.extend_from_slice(command);
    run_ok(&args).await.map(drop)
}

/// Deletes a sandbox and reports whether its record disappeared within `timeout`.
pub async fn delete_and_confirm(name: &str, timeout: Duration) -> (bool, String) {
    let response = run(&["sandbox", "delete", name]).await;
    let message = match &response {
        Ok(o) => format!("{}{}", o.stdout.trim(), o.stderr.trim()),
        Err(e) => format!("{e:#}"),
    };
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if get(name).await.is_err() {
            return (true, message);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    (false, message)
}

pub async fn get(name: &str) -> anyhow::Result<Value> {
    let output = run_ok(&["sandbox", "get", name, "-o", "json"]).await?;
    serde_json::from_str(&output.stdout).context("decode sandbox get")
}

pub async fn wait_ready(name: &str, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let phase = get(name)
            .await
            .ok()
            .and_then(|v| v.get("phase").and_then(Value::as_str).map(str::to_owned));
        match phase.as_deref() {
            Some("Ready") => return Ok(()),
            Some("Error") => bail!("sandbox {name} entered the Error phase"),
            _ if tokio::time::Instant::now() >= deadline => {
                bail!("sandbox {name} not Ready within {timeout:?}")
            }
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

pub async fn delete(name: &str) {
    let _ = run(&["sandbox", "delete", name]).await;
}

pub async fn stop(name: &str) -> anyhow::Result<()> {
    run_ok(&["sandbox", "stop", name]).await.map(drop)
}

pub async fn start(name: &str) -> anyhow::Result<()> {
    run_ok(&["sandbox", "start", name]).await?;
    wait_ready(name, Duration::from_secs(180)).await
}

pub async fn exec(name: &str, command: &[&str]) -> anyhow::Result<Output> {
    let mut args = vec!["sandbox", "exec", name, "--"];
    args.extend_from_slice(command);
    run(&args).await
}

/// Runs a probe subcommand inside a sandbox and decodes its JSON report.
pub async fn exec_probe(name: &str, probe_args: &[&str]) -> anyhow::Result<Value> {
    let mut command = vec!["probe"];
    command.extend_from_slice(probe_args);
    let output = exec(name, &command).await?;
    let text = output.stdout.trim();
    let start = text
        .find('{')
        .with_context(|| format!("no probe report from {name}: {}", output.stderr.trim()))?;
    serde_json::from_str(&text[start..]).context("decode probe report")
}

pub async fn expose(
    sandbox: &str,
    port: u16,
    service: &str,
    bearer_passthrough: bool,
) -> anyhow::Result<()> {
    let port = port.to_string();
    let mut args = vec!["service", "expose", sandbox, port.as_str(), service];
    if bearer_passthrough {
        args.extend_from_slice(&["--authorization-mode", "bearer-passthrough"]);
    }
    run_ok(&args).await.map(drop)
}

/// Reads the exposed URL of a sandbox service from `openshell service get`.
pub async fn service_url(sandbox: &str, service: Option<&str>) -> anyhow::Result<String> {
    let mut args = vec!["service", "get", sandbox];
    if let Some(service) = service {
        args.push(service);
    }
    let output = run_ok(&args).await?;
    let url = output
        .stdout
        .split_whitespace()
        .find(|token| token.starts_with("http://") || token.starts_with("https://"))
        .with_context(|| format!("no service URL in: {}", output.stdout.trim()))?;
    Ok(url.trim_end_matches('/').to_owned())
}

/// Starts a background forward. The forward process outlives this call, so its output
/// is discarded instead of piped: a piped output would stay open and block the caller.
pub async fn forward_start(port: u16, sandbox: &str) -> anyhow::Result<()> {
    let status = Command::new("openshell")
        .args(["forward", "start", &port.to_string(), sandbox, "-d"])
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("run openshell forward start")?;
    if !status.success() {
        bail!("openshell forward start {port} {sandbox} failed");
    }
    Ok(())
}

/// Stops every tracked forward that targets `sandbox`.
pub async fn forward_stop_all(sandbox: &str) {
    let Ok(output) = run(&["forward", "list", "--output", "json"]).await else {
        return;
    };
    let forwards: Vec<Value> = serde_json::from_str(&output.stdout).unwrap_or_default();
    for forward in forwards.iter().filter(|f| f["sandbox"] == sandbox) {
        if let Some(port) = forward["port"].as_u64() {
            let _ = run(&["forward", "stop", &port.to_string(), sandbox]).await;
        }
    }
}

pub async fn policy_set(sandbox: &str, policy: &std::path::Path) -> anyhow::Result<()> {
    let policy = policy.to_string_lossy();
    run_ok(&["policy", "set", sandbox, "--policy", &policy, "--wait"])
        .await
        .map(drop)
}
