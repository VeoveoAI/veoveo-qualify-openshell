//! Host-side targets: probe servers, the SurrealDB container, the probe image and host facts.

use anyhow::{Context, bail};
use serde::Serialize;
use std::{net::SocketAddr, process::Stdio, time::Duration};
use tokio::{process::Command, task::JoinHandle};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub id: String,
    pub os: String,
    pub arch: String,
    pub docker_server: String,
    pub docker_kernel: String,
    pub openshell: String,
    pub compute_driver: String,
}

async fn command_stdout(program: &str, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {program}"))?;
    if !output.status.success() {
        bail!(
            "{program} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub async fn info(openshell: String, compute_driver: String) -> anyhow::Result<HostInfo> {
    let os = std::env::consts::OS.to_owned();
    let arch = std::env::consts::ARCH.to_owned();
    Ok(HostInfo {
        id: format!("{os}-{arch}"),
        docker_server: command_stdout("docker", &["version", "--format", "{{.Server.Version}}"])
            .await?,
        docker_kernel: command_stdout("docker", &["info", "--format", "{{.KernelVersion}}"])
            .await?,
        os,
        arch,
        openshell,
        compute_driver,
    })
}

/// A free TCP port on all interfaces, so sandboxes can reach it through the gateway host.
pub fn free_port() -> anyhow::Result<u16> {
    let listener = std::net::TcpListener::bind("0.0.0.0:0")?;
    Ok(listener.local_addr()?.port())
}

/// Starts the probe HTTP and gRPC servers in this process.
pub fn spawn_server(http_port: u16, grpc_port: u16) -> JoinHandle<anyhow::Result<()>> {
    let http = SocketAddr::from(([0, 0, 0, 0], http_port));
    let grpc = SocketAddr::from(([0, 0, 0, 0], grpc_port));
    tokio::spawn(crate::server::serve(http, grpc))
}

pub async fn build_probe_image(tag: &str) -> anyhow::Result<()> {
    let root = env!("CARGO_MANIFEST_DIR");
    let revision = command_stdout("git", &["-C", root, "rev-parse", "HEAD"]).await?;
    let status = Command::new("docker")
        .args(["build", "-q", "-t", tag])
        .args([
            "--build-arg",
            &format!("VERSION={}", env!("CARGO_PKG_VERSION")),
        ])
        .args(["--build-arg", &format!("REVISION={revision}")])
        .arg(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .await
        .context("run docker build")?;
    if !status.success() {
        bail!("docker build of {tag} failed");
    }
    Ok(())
}

pub struct Surreal {
    pub container: String,
    pub password: String,
}

impl Surreal {
    /// Starts SurrealDB 3.3.0 in memory, published on two host ports that the policy
    /// treats as an uninspected endpoint and a native TCP endpoint.
    pub async fn start(
        container: &str,
        inspected_port: u16,
        tcp_port: u16,
    ) -> anyhow::Result<Self> {
        let password = format!("q{:x}{:x}", crate::now_ms(), std::process::id());
        let publish_a = format!("0.0.0.0:{inspected_port}:8000");
        let publish_b = format!("0.0.0.0:{tcp_port}:8000");
        command_stdout(
            "docker",
            &[
                "run",
                "-d",
                "--name",
                container,
                "-p",
                &publish_a,
                "-p",
                &publish_b,
                "surrealdb/surrealdb:v3.3.0",
                "start",
                "--user",
                "root",
                "--pass",
                &password,
                "memory",
            ],
        )
        .await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        while tokio::net::TcpStream::connect(("127.0.0.1", inspected_port))
            .await
            .is_err()
        {
            if tokio::time::Instant::now() >= deadline {
                bail!("SurrealDB did not listen within 60 seconds");
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(Self {
            container: container.to_owned(),
            password,
        })
    }

    pub async fn stop(&self) {
        let _ = command_stdout("docker", &["rm", "-f", &self.container]).await;
    }
}

/// Runs the Rerun Catalog SDK probe from the probe image on the host network.
pub async fn catalog_probe(image: &str, url: &str) -> anyhow::Result<serde_json::Value> {
    let output = command_stdout(
        "docker",
        &[
            "run",
            "--rm",
            "--network",
            "host",
            "-e",
            "RERUN_ANALYTICS=false",
            image,
            "/usr/local/rerun/bin/python",
            "/usr/local/share/probe/catalog_probe.py",
            url,
        ],
    )
    .await?;
    let start = output.find('{').context("no catalog probe report")?;
    serde_json::from_str(&output[start..]).context("decode catalog probe report")
}
