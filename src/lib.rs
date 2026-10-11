//! Probes and the qualification harness for running Veoveo component environments on OpenShell.
//!
//! The `probe` binary runs inside sandboxes and on the host. The harness binary creates
//! sandboxes, runs the scenarios and writes one report per OpenShell release and host.

pub mod client;
pub mod grpc;
pub mod harness;
pub mod probes;
pub mod server;
pub mod stats;
pub mod surreal;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

/// Deterministic body byte at `offset`, shared by the server and the verifier.
pub fn pattern_byte(offset: u64) -> u8 {
    (offset % 251) as u8
}
