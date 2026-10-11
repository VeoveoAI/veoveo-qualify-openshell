//! Typed OpenShell `version: 1` policies, written as JSON, which OpenShell reads as YAML.

use serde::Serialize;
use std::{collections::BTreeMap, path::Path};

pub const HOST: &str = "host.openshell.internal";
const PROBE: &str = "/usr/local/bin/probe";

#[derive(Serialize)]
pub struct Policy {
    version: u32,
    filesystem_policy: Filesystem,
    network_policies: BTreeMap<&'static str, Rule>,
}

#[derive(Serialize)]
struct Filesystem {
    include_workdir: bool,
    read_only: Vec<&'static str>,
    read_write: Vec<&'static str>,
}

#[derive(Serialize)]
struct Rule {
    endpoints: Vec<Endpoint>,
    binaries: Vec<Binary>,
}

#[derive(Serialize)]
struct Binary {
    path: &'static str,
}

#[derive(Serialize, Default)]
struct Endpoint {
    host: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enforcement: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    access: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<McpOptions>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rules: Vec<Allow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny_rules: Vec<McpDeny>,
}

#[derive(Serialize)]
struct McpOptions {
    versions: Vec<&'static str>,
    allow_all_known_mcp_methods: bool,
}

#[derive(Serialize)]
struct Allow {
    allow: RestMatch,
}

#[derive(Serialize)]
struct RestMatch {
    method: &'static str,
    path: &'static str,
}

#[derive(Serialize)]
struct McpDeny {
    method: &'static str,
    tool: &'static str,
}

/// Host ports that client sandboxes may reach on the gateway host.
pub struct HostPorts {
    pub plain_http: u16,
    pub plain_grpc: u16,
    pub mcp_http: u16,
    pub websocket_http: u16,
    pub tcp_grpc: u16,
    pub surreal_inspected: u16,
    pub surreal_tcp: u16,
}

pub const DENIED_TOOL: &str = "forbidden_tool";

fn filesystem(extra_read_write: &[&'static str]) -> Filesystem {
    let mut read_write = vec!["/tmp", "/dev/null"];
    read_write.extend_from_slice(extra_read_write);
    Filesystem {
        include_workdir: true,
        read_only: vec![
            "/bin",
            "/usr",
            "/lib",
            "/lib64",
            "/etc",
            "/proc",
            "/dev/urandom",
            "/var/log",
        ],
        read_write,
    }
}

fn binaries(paths: &[&'static str]) -> Vec<Binary> {
    paths.iter().map(|path| Binary { path }).collect()
}

/// A server sandbox needs no outbound access.
pub fn server() -> Policy {
    Policy {
        version: 1,
        filesystem_policy: filesystem(&[]),
        network_policies: BTreeMap::new(),
    }
}

/// A client sandbox reaches the host targets through each endpoint type under test.
pub fn client(ports: &HostPorts) -> Policy {
    let probe = || binaries(&[PROBE]);
    let mut rules = BTreeMap::new();
    rules.insert(
        "host_plain",
        Rule {
            endpoints: vec![Endpoint {
                host: HOST,
                ports: Some(vec![ports.plain_http, ports.plain_grpc]),
                ..Default::default()
            }],
            binaries: probe(),
        },
    );
    rules.insert(
        "host_mcp",
        Rule {
            endpoints: vec![Endpoint {
                host: HOST,
                port: Some(ports.mcp_http),
                protocol: Some("mcp"),
                enforcement: Some("enforce"),
                mcp: Some(McpOptions {
                    versions: vec!["2026-07-28"],
                    allow_all_known_mcp_methods: true,
                }),
                deny_rules: vec![McpDeny {
                    method: "tools/call",
                    tool: DENIED_TOOL,
                }],
                ..Default::default()
            }],
            binaries: probe(),
        },
    );
    rules.insert(
        "host_websocket",
        Rule {
            endpoints: vec![Endpoint {
                host: HOST,
                port: Some(ports.websocket_http),
                protocol: Some("websocket"),
                enforcement: Some("audit"),
                access: Some("full"),
                ..Default::default()
            }],
            binaries: probe(),
        },
    );
    rules.insert(
        "host_tcp",
        Rule {
            endpoints: vec![Endpoint {
                host: HOST,
                port: Some(ports.tcp_grpc),
                protocol: Some("tcp"),
                ..Default::default()
            }],
            binaries: probe(),
        },
    );
    rules.insert(
        "surrealdb",
        Rule {
            endpoints: vec![
                Endpoint {
                    host: HOST,
                    port: Some(ports.surreal_inspected),
                    ..Default::default()
                },
                Endpoint {
                    host: HOST,
                    port: Some(ports.surreal_tcp),
                    protocol: Some("tcp"),
                    ..Default::default()
                },
            ],
            binaries: probe(),
        },
    );
    rules.insert(
        "crates_io_https",
        Rule {
            endpoints: vec![Endpoint {
                host: "index.crates.io",
                port: Some(443),
                ..Default::default()
            }],
            binaries: probe(),
        },
    );
    Policy {
        version: 1,
        filesystem_policy: filesystem(&[]),
        network_policies: rules,
    }
}

/// A development sandbox installs toolchains, components and crates and fetches from GitHub.
pub fn dev() -> Policy {
    let cargo_and_rustup = || {
        binaries(&[
            "/usr/local/cargo/bin/*",
            "/usr/local/rustup/toolchains/*/bin/cargo",
        ])
    };
    let mut rules = BTreeMap::new();
    rules.insert(
        "rust_toolchains",
        Rule {
            endpoints: vec![Endpoint {
                host: "static.rust-lang.org",
                port: Some(443),
                ..Default::default()
            }],
            binaries: binaries(&["/usr/local/cargo/bin/*"]),
        },
    );
    rules.insert(
        "crates_io",
        Rule {
            endpoints: ["index.crates.io", "static.crates.io", "crates.io"]
                .into_iter()
                .map(|host| Endpoint {
                    host,
                    port: Some(443),
                    ..Default::default()
                })
                .collect(),
            binaries: cargo_and_rustup(),
        },
    );
    rules.insert(
        "github_fetch",
        Rule {
            endpoints: vec![Endpoint {
                host: "github.com",
                port: Some(443),
                protocol: Some("rest"),
                enforcement: Some("enforce"),
                rules: vec![
                    Allow {
                        allow: RestMatch {
                            method: "GET",
                            path: "/**/info/refs*",
                        },
                    },
                    Allow {
                        allow: RestMatch {
                            method: "POST",
                            path: "/**/git-upload-pack",
                        },
                    },
                ],
                ..Default::default()
            }],
            binaries: binaries(&[
                "/usr/bin/git",
                "/usr/lib/git-core/*",
                "/usr/local/cargo/bin/*",
                "/usr/local/rustup/toolchains/*/bin/cargo",
            ]),
        },
    );
    Policy {
        version: 1,
        filesystem_policy: filesystem(&["/usr/local/rustup", "/usr/local/cargo"]),
        network_policies: rules,
    }
}

pub fn write(policy: &Policy, path: &Path) -> anyhow::Result<()> {
    std::fs::write(path, serde_json::to_vec_pretty(policy)?)?;
    Ok(())
}
