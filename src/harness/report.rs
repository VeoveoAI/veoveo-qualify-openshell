//! Qualification outcomes and the per-release, per-host report.

use super::host::HostInfo;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The behavior Veoveo relies on works.
    Pass,
    /// The behavior Veoveo relies on is broken.
    Fail,
    /// A documented limitation of this release is still present.
    Limit,
    /// A documented limitation of this release no longer appears.
    LimitLifted,
    /// The scenario does not apply to this host.
    Skip,
}

#[derive(Serialize)]
pub struct Outcome {
    pub id: &'static str,
    pub rule: &'static str,
    pub status: Status,
    pub details: Value,
}

impl Outcome {
    pub fn check(id: &'static str, rule: &'static str, passed: bool, details: Value) -> Self {
        let status = if passed { Status::Pass } else { Status::Fail };
        Self {
            id,
            rule,
            status,
            details,
        }
    }

    /// A documented limitation: `limited` is true while the release still shows it.
    pub fn limit(id: &'static str, rule: &'static str, limited: bool, details: Value) -> Self {
        let status = if limited {
            Status::Limit
        } else {
            Status::LimitLifted
        };
        Self {
            id,
            rule,
            status,
            details,
        }
    }

    pub fn error(id: &'static str, rule: &'static str, error: anyhow::Error) -> Self {
        Self {
            id,
            rule,
            status: Status::Fail,
            details: serde_json::json!({"error": format!("{error:#}")}),
        }
    }

    pub fn skip(id: &'static str, rule: &'static str, reason: &str) -> Self {
        Self {
            id,
            rule,
            status: Status::Skip,
            details: serde_json::json!({"reason": reason}),
        }
    }
}

#[derive(Serialize)]
pub struct Report {
    pub format: &'static str,
    pub harness_version: &'static str,
    pub started_at_ms: u64,
    pub duration_ms: u64,
    pub stream_seconds: u64,
    pub host: HostInfo,
    pub outcomes: Vec<Outcome>,
}

impl Report {
    pub fn failures(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.status == Status::Fail)
            .count()
    }

    pub fn write(&self, results_dir: &Path) -> anyhow::Result<PathBuf> {
        let dir = results_dir.join(&self.host.openshell);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.host.id));
        std::fs::write(&path, serde_json::to_vec_pretty(self)?)?;
        Ok(path)
    }

    pub fn print_summary(&self) {
        println!(
            "OpenShell {} on {} (Docker {}, kernel {}, driver {})",
            self.host.openshell,
            self.host.id,
            self.host.docker_server,
            self.host.docker_kernel,
            self.host.compute_driver
        );
        for outcome in &self.outcomes {
            let status = serde_json::to_value(outcome.status)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            println!("  {status:<12} {:<34} {}", outcome.id, outcome.rule);
        }
        println!(
            "{} scenarios, {} failed",
            self.outcomes.len(),
            self.failures()
        );
    }
}
