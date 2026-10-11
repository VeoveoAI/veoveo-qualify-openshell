//! Runs the OpenShell qualification against the local gateway and writes the report.

use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use veoveo_qualify_openshell::{
    harness::{host, openshell, report::Report, scenarios},
    now_ms,
};

#[derive(Parser)]
#[command(name = "veoveo-qualify-openshell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create sandboxes on the local OpenShell gateway, run every scenario and write the report.
    Run {
        /// Duration of each streaming scenario; use 1800 for the endurance profile.
        #[arg(long, default_value_t = 15)]
        stream_seconds: u64,
        /// Size of each large-transfer scenario.
        #[arg(long, default_value_t = 512)]
        transfer_mib: u64,
        /// Size of the cache file in the persistence scenario.
        #[arg(long, default_value_t = 512)]
        cache_mib: u64,
        /// Directory that receives `<openshell-version>/<os>-<arch>.json`.
        #[arg(long, default_value = "results")]
        results_dir: PathBuf,
        /// Keep sandboxes and the SurrealDB container for inspection.
        #[arg(long)]
        keep: bool,
        /// Also run lifecycle scenarios that can leave an undeletable record on the gateway.
        #[arg(long)]
        lifecycle: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Command::Run {
        stream_seconds,
        transfer_mib,
        cache_mib,
        results_dir,
        keep,
        lifecycle,
    } = Cli::parse().command;

    let started_at_ms = now_ms();
    let openshell_version = openshell::version()
        .await
        .context("OpenShell CLI is required")?;
    let compute_driver = openshell::compute_driver().await?;
    let host = host::info(openshell_version, compute_driver).await?;
    let gpu = cfg!(target_os = "linux") && std::path::Path::new("/dev/nvidiactl").exists();

    let run_id = format!("{:x}", started_at_ms % 0xFFFFFF);
    let image = "veoveo-qualify-openshell-probe:local".to_owned();
    eprintln!("building {image}");
    host::build_probe_image(&image).await?;

    let workdir = std::env::temp_dir().join(format!("veoveo-qualify-openshell-{run_id}"));
    std::fs::create_dir_all(&workdir)?;
    let settings = scenarios::Settings {
        run_id,
        image,
        stream_seconds,
        transfer_mib,
        cache_mib,
        gpu,
        keep,
        lifecycle,
    };
    eprintln!(
        "running scenarios on OpenShell {} ({})",
        host.openshell, host.id
    );
    let outcomes = scenarios::run(&settings, &workdir).await?;

    let report = Report {
        format: "veoveo.ai/openshell-qualification/v1",
        harness_version: env!("CARGO_PKG_VERSION"),
        started_at_ms,
        duration_ms: now_ms() - started_at_ms,
        stream_seconds,
        host,
        outcomes,
    };
    let path = report.write(&results_dir)?;
    report.print_summary();
    println!("report: {}", path.display());
    if report.failures() > 0 {
        std::process::exit(1);
    }
    Ok(())
}
