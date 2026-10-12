//! Git push through an attached GitHub provider, limited by sandbox policy to one repository.

use super::{RunContext, Settings, shell};
use crate::harness::{
    openshell::{self, SandboxSpec},
    policy,
    report::Outcome,
};
use serde_json::json;

/// A provider created from a GitHub token that can write to both repositories, so that
/// only sandbox policy separates them.
pub struct GitHubTarget {
    pub provider: String,
    pub push_repository: String,
    pub denied_repository: String,
}

const ID: &str = "git.provider_push";
const RULE: &str = "with a GitHub provider attached, a sandbox pushes to the one repository its policy allows, is refused on another and holds only a placeholder for the token";

const PLACEHOLDER: &str = r#"case "$GITHUB_TOKEN" in openshell:resolve:*) ;; *) exit 1 ;; esac \
    && ! env | grep -q -E '=(github_pat_|gh[pousr]_)'"#;
const CREDENTIAL_HELPER: &str = r#"git config --global user.name qualify \
    && git config --global user.email qualify@veoveo.ai \
    && git config --global credential.helper '!f() { echo username=x-access-token; echo "password=$GITHUB_TOKEN"; }; f'"#;

fn push(repository: &str, directory: &str, branch: &str) -> String {
    format!(
        "rm -rf /sandbox/{directory} && git clone -q --depth 1 https://github.com/{repository}.git /sandbox/{directory} \
         && cd /sandbox/{directory} && git checkout -q -b {branch} && git commit -q --allow-empty -m qualify \
         && git push -q origin {branch}"
    )
}

pub async fn provider_push(settings: &Settings, context: &RunContext) -> Outcome {
    let Some(target) = &settings.github else {
        return Outcome::skip(
            ID,
            RULE,
            "run with --github-provider <name>, a provider whose token can write to both repositories",
        );
    };
    let name = format!("vv-qual-{}-git", settings.run_id);
    let policy_path = context.policies.join("git.yaml");
    if let Err(error) = policy::write(&policy::git_push(&target.push_repository), &policy_path) {
        return Outcome::error(ID, RULE, error);
    }
    let spec = SandboxSpec {
        name: name.clone(),
        image: settings.image.clone(),
        policy: policy_path,
        env: vec![("HOME".into(), "/sandbox".into())],
        expose: None,
        restart_on_failure: false,
        gpu: false,
        providers: vec![target.provider.clone()],
        command: vec!["sleep".into(), "infinity".into()],
    };
    if let Err(error) = openshell::create(&spec).await {
        openshell::delete(&name).await;
        return Outcome::error(ID, RULE, error);
    }

    let branch = format!("qualify-{}", settings.run_id);
    let (placeholder, _) = shell(&name, PLACEHOLDER).await;
    let (helper, helper_output) = shell(&name, CREDENTIAL_HELPER).await;
    let (pushed, push_output) =
        shell(&name, &push(&target.push_repository, "allowed", &branch)).await;
    let (other_pushed, other_output) =
        shell(&name, &push(&target.denied_repository, "denied", &branch)).await;
    let (cleaned, cleanup_output) = shell(
        &name,
        &format!("cd /sandbox/allowed && git push -q origin --delete {branch}"),
    )
    .await;
    if !settings.keep {
        openshell::delete(&name).await;
    }

    let refused = !other_pushed && other_output.contains("403");
    let step = |ok: bool, output: String| json!({"ok": ok, "outputTail": output});
    Outcome::check(
        ID,
        RULE,
        placeholder && helper && pushed && refused && cleaned,
        json!({
            "provider": target.provider,
            "pushRepository": target.push_repository,
            "deniedRepository": target.denied_repository,
            "branch": branch,
            "placeholderOnly": placeholder,
            "credentialHelper": step(helper, helper_output),
            "pushAllowed": step(pushed, push_output),
            "pushRefused": step(refused, other_output),
            "branchDeleted": step(cleaned, cleanup_output),
        }),
    )
}
