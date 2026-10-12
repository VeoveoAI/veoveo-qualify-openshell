//! A provider secret that resolves only at the endpoint a sandbox policy binds it to,
//! the mechanism an installation's registration secret relies on.

use super::{RunContext, Settings, shell};
use crate::{
    harness::{
        host,
        openshell::{self, SandboxSpec},
        policy,
        report::Outcome,
    },
    sha256_hex,
};
use anyhow::{Context, anyhow};
use serde_json::{Value, json};
use std::io::Read;

const ID: &str = "provider.bound_secret";
const RULE: &str = "an endpointless provider's secret reaches only the endpoint a sandbox policy binds it to: the sandbox holds a placeholder, the bound endpoint receives the value and another allowed endpoint is refused";
const PROFILE_ID: &str = "vv-qual-bound-secret";
const ENV_KEY: &str = "VEOVEO_QUALIFY_BOUND_SECRET";

pub async fn bound_secret(settings: &Settings, context: &RunContext) -> Outcome {
    let name = format!("vv-qual-{}-bound", settings.run_id);
    let bound_port = host::free_port();
    let other_port = host::free_port();
    let (Ok(bound_port), Ok(other_port)) = (bound_port, other_port) else {
        return Outcome::error(ID, RULE, anyhow!("no free host ports"));
    };
    let servers = [
        host::spawn_server(bound_port, host::free_port().unwrap_or(0)),
        host::spawn_server(other_port, host::free_port().unwrap_or(0)),
    ];
    let outcome = match run(settings, context, &name, bound_port, other_port).await {
        Ok(outcome) => outcome,
        Err(error) => Outcome::error(ID, RULE, error),
    };
    if !settings.keep {
        // A provider cannot be deleted while attached, so the sandbox goes first.
        let _ = openshell::delete_and_confirm(&name, std::time::Duration::from_secs(60)).await;
        openshell::provider_delete(&name).await;
        openshell::profile_delete(PROFILE_ID).await;
    }
    for server in servers {
        server.abort();
    }
    outcome
}

fn fresh_secret() -> anyhow::Result<String> {
    let mut bytes = [0u8; 24];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

async fn run(
    settings: &Settings,
    context: &RunContext,
    name: &str,
    bound_port: u16,
    other_port: u16,
) -> anyhow::Result<Outcome> {
    let profile = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("providers/vv-qual-bound-secret.yaml");
    openshell::profile_delete(PROFILE_ID).await;
    openshell::profile_import(&profile).await?;
    let secret = fresh_secret()?;
    openshell::provider_create(name, PROFILE_ID, ENV_KEY, &secret).await?;

    let policy_path = context.policies.join("bound.yaml");
    policy::write(
        &policy::bound_secret(name, bound_port, other_port),
        &policy_path,
    )?;
    openshell::create(&SandboxSpec {
        name: name.to_owned(),
        image: settings.image.clone(),
        policy: policy_path,
        env: vec![("HOME".into(), "/sandbox".into())],
        expose: None,
        restart_on_failure: false,
        gpu: false,
        providers: vec![name.to_owned()],
        command: vec!["sleep".into(), "infinity".into()],
    })
    .await
    .context("create bound-secret sandbox")?;

    let host = policy::HOST;
    let script = format!(
        r#"case "${ENV_KEY}" in openshell:resolve:*) echo placeholder=true ;; *) echo placeholder=false ;; esac
echo "bound=$(curl -s -m 10 -H "Authorization: Bearer ${ENV_KEY}" http://{host}:{bound_port}/auth)"
echo "other=$(curl -s -m 10 -w ' status=%{{http_code}}' -H "Authorization: Bearer ${ENV_KEY}" http://{host}:{other_port}/auth)""#
    );
    let (ok, output) = shell(name, &script).await;
    let field = |key: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_owned()
    };
    let placeholder = field("placeholder") == "true";
    let bound: Value = serde_json::from_str(&field("bound")).unwrap_or(Value::Null);
    let received = bound
        .pointer("/authorization/bearerSha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let delivered = !received.is_empty() && received == sha256_hex(secret.as_bytes());
    let other = field("other");
    let refused = other.contains("credential_endpoint_mismatch") && other.ends_with("status=403");
    Ok(Outcome::check(
        ID,
        RULE,
        ok && placeholder && delivered && refused,
        json!({
            "placeholderOnly": placeholder,
            "boundEndpointReceivedSecret": delivered,
            "boundResponse": bound,
            "unboundEndpointResponse": other,
        }),
    ))
}
