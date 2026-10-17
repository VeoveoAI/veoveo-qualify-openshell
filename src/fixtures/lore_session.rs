//! Disposable qualification workload. Captures the native reference once for its whole lifetime.
use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
fn launch_id() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
struct Session {
    reference: String,
    identity: String,
    repository: String,
    branch: String,
    forbidden: String,
}
impl Session {
    fn lore(&self, dir: &str, args: &[&str]) -> Result<String, String> {
        let out = Command::new("/usr/local/bin/lore")
            .current_dir(dir)
            .args([
                "-P",
                "--identity",
                &self.identity,
                "--access-token",
                &self.reference,
            ])
            .args(args)
            .env("LORE_AUTH_TOKEN", &self.reference)
            .output()
            .map_err(|_| "could not start Lore".to_string())?;
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        if text.len() > 65536 {
            return Err("output bound exceeded".into());
        }
        if out.status.success() {
            Ok(text)
        } else {
            Err(text)
        }
    }
    fn clone(&self, dir: &str, branch: &str) -> Result<String, String> {
        self.lore(
            "/sandbox",
            &[
                "repository",
                "clone",
                &self.repository,
                dir,
                "--branch",
                branch,
            ],
        )
    }
    fn edit_push(&self, dir: &str, file: &str, value: &str) -> Result<String, String> {
        let path = format!("{dir}/{file}");
        if Path::new(&path).exists() {
            self.lore(dir, &["dirty", file])?;
        }
        fs::write(path, value).map_err(|_| "write failed".to_string())?;
        self.lore(dir, &["stage", file])?;
        self.lore(dir, &["commit", value.trim()])?;
        self.lore(dir, &["push"])
    }
    fn subscribe(&self) -> io::Result<Child> {
        let stdout = fs::File::create("/sandbox/notifications")?;
        let stderr = fs::File::create("/sandbox/notification-errors")?;
        Command::new("/usr/local/bin/lore")
            .current_dir("/sandbox/edit")
            .args([
                "-P",
                "--identity",
                &self.identity,
                "--access-token",
                &self.reference,
                "notification",
                "subscribe",
                "900",
            ])
            .env("LORE_AUTH_TOKEN", &self.reference)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let launch_id = launch_id()?;
    let args: Vec<String> = std::env::args().collect();
    let reference = std::env::var("LORE_AUTH_TOKEN")?;
    assert!(
        reference.starts_with("openshell:resolve:"),
        "expected native reference"
    );
    let session = Session {
        reference,
        identity: args[1].clone(),
        repository: args[2].clone(),
        branch: args[3].clone(),
        forbidden: args[4].clone(),
    };
    let start = Instant::now();
    if !Path::new("/sandbox/edit").exists() {
        session
            .clone("/sandbox/edit", &session.branch)
            .map_err(io::Error::other)?;
    }
    let mut previous = fs::read_to_string("/sandbox/command").unwrap_or_default();
    let mut subscription: Option<Child> = None;
    fs::write("/sandbox/ready", format!("{launch_id} captured-once"))?;
    while start.elapsed() < Duration::from_secs(900) {
        if let Ok(command) = fs::read_to_string("/sandbox/command") {
            if command != previous {
                previous = command.clone();
                let (id, action) = command.trim().split_once(' ').ok_or("invalid command")?;
                let result = match action {
                    "ping" => Ok("captured-once".into()),
                    "read" => {
                        session.lore("/sandbox", &["repository", "info", &session.repository])
                    }
                    "forbidden" => {
                        session.lore("/sandbox", &["repository", "info", &session.forbidden])
                    }
                    "push" => session.edit_push(
                        "/sandbox/edit",
                        "session.txt",
                        &format!(
                            "{id} {:x}\n",
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs()
                        ),
                    ),
                    "verify" => session
                        .clone("/sandbox/verify", &session.branch)
                        .and_then(|_| {
                            fs::read_to_string("/sandbox/verify/session.txt")
                                .map_err(|_| "content missing".into())
                        }),
                    "wrong" => {
                        // Another legitimate author may have advanced this branch.
                        // A fresh clone makes every negative attempt pushable.
                        let dir = format!("/sandbox/wrong-{id}");
                        session.clone(&dir, "other-author")?;
                        session.edit_push(&dir, "wrong.txt", &format!("{id}\n"))
                    }
                    "protected" => {
                        session.edit_push("/sandbox/edit", "protected.txt", &format!("{id}\n"))
                    }
                    "protection" => {
                        session.lore("/sandbox/edit", &["branch", "metadata", "get", "protect"])
                    }
                    "subscribe" => {
                        if let Some(mut child) = subscription.take() {
                            let _ = child.kill();
                            let _ = child.wait();
                        }
                        subscription = Some(session.subscribe()?);
                        Ok("started".into())
                    }
                    _ => Err("unknown action".into()),
                };
                let (code, text) = match result {
                    Ok(text) => (0, text),
                    Err(text) => (1, text),
                };
                let mut out = fs::File::create("/sandbox/reply.next")?;
                write!(out, "{id} {code} {launch_id}\n{text}")?;
                out.sync_all()?;
                fs::rename("/sandbox/reply.next", "/sandbox/reply")?;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    if let Some(mut child) = subscription {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn each_launch_has_a_unique_marker_without_relying_on_pid() {
        let first = super::launch_id().unwrap();
        let second = super::launch_id().unwrap();
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }
}
