//! Host-side targets: probe servers, the PostgreSQL container, the probe image and host facts.

use anyhow::{Context, bail};
use serde::Serialize;
use std::{io::Read, net::SocketAddr, process::Stdio, time::Duration};
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

/// Random lowercase hexadecimal from the operating system, for throwaway secrets.
pub fn fresh_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// The official PostgreSQL 18.6 image.
const POSTGRES_IMAGE: &str =
    "postgres:18.6-trixie@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336";

pub struct Postgres {
    pub container: String,
    pub password: String,
}

impl Postgres {
    pub const USER: &str = "probe";
    pub const DATABASE: &str = "probe";

    /// Starts PostgreSQL 18.6 on a tmpfs data directory, published on two host ports that
    /// the policy treats as an endpoint without a protocol and as a `tcp` endpoint, and
    /// waits until it accepts connections. A container that never becomes ready is removed.
    pub async fn start(
        container: &str,
        inspected_port: u16,
        tcp_port: u16,
    ) -> anyhow::Result<Self> {
        let postgres = Self {
            container: container.to_owned(),
            password: fresh_secret()?,
        };
        let publish_a = format!("0.0.0.0:{inspected_port}:5432");
        let publish_b = format!("0.0.0.0:{tcp_port}:5432");
        let user = format!("POSTGRES_USER={}", Self::USER);
        let database = format!("POSTGRES_DB={}", Self::DATABASE);
        // `-e POSTGRES_PASSWORD` without a value copies it from the client's environment,
        // which keeps the password out of process arguments.
        let output = Command::new("docker")
            .args(["run", "-d", "--name", container])
            .args(["--tmpfs", "/var/lib/postgresql"])
            .args(["-e", &user, "-e", &database, "-e", "POSTGRES_PASSWORD"])
            .args(["-p", &publish_a, "-p", &publish_b, POSTGRES_IMAGE])
            .env("POSTGRES_PASSWORD", &postgres.password)
            .stdin(Stdio::null())
            .output()
            .await
            .context("run docker run")?;
        if !output.status.success() {
            postgres.stop().await;
            bail!(
                "docker run of {POSTGRES_IMAGE} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        if let Err(error) = postgres.wait_ready(Duration::from_secs(60)).await {
            let logs = Command::new("docker")
                .args(["logs", "--tail", "20", container])
                .stdin(Stdio::null())
                .output()
                .await
                .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
                .unwrap_or_default();
            postgres.stop().await;
            return Err(error.context(format!("PostgreSQL log tail: {logs}")));
        }
        Ok(postgres)
    }

    /// Waits until `pg_isready` inside the container reaches the server over TCP. The
    /// image's initialization server listens only on a socket, so only the final server
    /// answers.
    async fn wait_ready(&self, timeout: Duration) -> anyhow::Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let ready = Command::new("docker")
                .args([
                    "exec",
                    &self.container,
                    "pg_isready",
                    "-q",
                    "-h",
                    "127.0.0.1",
                ])
                .args(["-p", "5432", "-U", Self::USER, "-d", Self::DATABASE])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .is_ok_and(|status| status.success());
            if ready {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("PostgreSQL did not accept connections within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    pub async fn stop(&self) {
        let _ = command_stdout("docker", &["rm", "-f", "-v", &self.container]).await;
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
