//! Integration tests for `shellflow service init` and `shellflow secret
//! keys-check`: the two controller-side commands that replace the infra
//! repository's bash scripts.
//!
//! `service init` writes into the current working directory, so every test
//! runs the binary with `current_dir` pointed at a temp repo.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

type TestResult<T> = std::result::Result<T, String>;

fn shellflow() -> Command {
    // No `--no-color`: global run flags conflict with subcommands
    // (`args_conflicts_with_subcommands`), and these subcommands never color.
    Command::new(env!("CARGO_BIN_EXE_shellflow"))
}

fn status(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// A throwaway repository root (cwd for `service init`).
struct Repo {
    dir: PathBuf,
}

impl Repo {
    fn new(name: &str) -> TestResult<Self> {
        let dir =
            std::env::temp_dir().join(format!("shellflow-svcinit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(Self { dir })
    }

    /// Run `service init` with the repo as cwd.
    fn init(&self, args: &[&str]) -> TestResult<Output> {
        let mut cmd = shellflow();
        cmd.arg("service").arg("init").args(args).current_dir(&self.dir);
        cmd.output().map_err(|e| e.to_string())
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.dir.join(rel)
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Create an identity + encrypted env file through the real CLI.
fn encrypted_env(dir: &Path, name: &str, plaintext: &str) -> TestResult<(PathBuf, PathBuf)> {
    let key = dir.join(format!("{name}-keys.txt"));
    let out = shellflow()
        .args(["keys", "generate", "-o"])
        .arg(&key)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "keys generate failed: {}", String::from_utf8_lossy(&out.stderr));
    let out =
        shellflow().args(["keys", "public", "-i"]).arg(&key).output().map_err(|e| e.to_string())?;
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let plain = dir.join(format!("{name}.env"));
    fs::write(&plain, plaintext).map_err(|e| e.to_string())?;
    let env_age = dir.join(format!("{name}.env.age"));
    let out = shellflow()
        .args(["secret", "encrypt", "-r", &pubkey, "-o"])
        .arg(&env_age)
        .arg(&plain)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "secret encrypt failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok((key, env_age))
}

#[test]
fn service_init_creates_the_three_files() -> TestResult<()> {
    let repo = Repo::new("basic")?;
    let out = repo.init(&["myapp", "--host", "api", "--host", "trade"])?;
    assert_eq!(status(&out), 0, "init failed: {}", String::from_utf8_lossy(&out.stderr));

    for rel in [
        "services/myapp/myapp.json5.tmpl",
        "services/myapp/myapp.service",
        "playbooks/deploy-myapp.sh",
    ] {
        assert!(repo.path(rel).exists(), "missing {rel}");
    }
    let unit =
        fs::read_to_string(repo.path("services/myapp/myapp.service")).map_err(|e| e.to_string())?;
    assert!(unit.contains("User=myapp"));
    assert!(unit.contains("cred-env exec"));
    assert!(unit.contains("cred-env render"));

    let playbook =
        fs::read_to_string(repo.path("playbooks/deploy-myapp.sh")).map_err(|e| e.to_string())?;
    assert!(playbook.contains("# @server api"));
    assert!(playbook.contains("# @server trade"));
    assert!(playbook.contains("# @secrets services/myapp/{host}.env.age"));
    assert!(playbook.contains("cred-env credstore-install"));
    assert!(!playbook.contains("__SVC__"), "unreplaced token in playbook");
    assert!(!playbook.contains("__HOST__"), "unreplaced token in playbook");

    // The playbook must be executable (it is invoked directly).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(repo.path("playbooks/deploy-myapp.sh"))
            .map_err(|e| e.to_string())?
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "playbook must be 0755, got {mode:o}");
    }
    Ok(())
}

#[test]
fn service_init_generated_playbook_passes_syntax_check() -> TestResult<()> {
    let repo = Repo::new("check")?;
    let out = repo.init(&["myapp", "--host", "api"])?;
    assert_eq!(status(&out), 0, "init failed: {}", String::from_utf8_lossy(&out.stderr));

    // Create the per-host encrypted env the playbook references, then run the
    // real `-k` check through the CLI (parse + identity + bash -n).
    let svc_dir = repo.path("services/myapp");
    let (key, _) = encrypted_env(&svc_dir, "api", "LISTEN_ENDPOINT=tcp/10.0.0.1:7447\n")?;
    let out = shellflow()
        .args(["-k", "--local", "-i"])
        .arg(&key)
        .arg(repo.path("playbooks/deploy-myapp.sh"))
        .current_dir(&repo.dir)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(
        status(&out),
        0,
        "generated playbook failed -k: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

#[test]
fn service_init_refuses_to_overwrite() -> TestResult<()> {
    let repo = Repo::new("overwrite")?;
    let out = repo.init(&["myapp"])?;
    assert_eq!(status(&out), 0, "first init failed: {}", String::from_utf8_lossy(&out.stderr));
    let out = repo.init(&["myapp"])?;
    assert_ne!(status(&out), 0, "a second init must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("refusing to overwrite"), "unclear error: {stderr}");
    Ok(())
}

#[test]
fn service_init_rejects_bad_names() -> TestResult<()> {
    let repo = Repo::new("badname")?;
    for bad in ["Api", "1app", "../evil", "a b", "app_svc"] {
        let out = repo.init(&[bad])?;
        assert_ne!(status(&out), 0, "`{bad}` must be rejected");
    }
    // Nothing must have been written for the rejected names.
    assert!(!repo.path("services").exists(), "no service dir for rejected names");
    Ok(())
}

#[test]
fn service_init_defaults_to_api() -> TestResult<()> {
    let repo = Repo::new("defaulthost")?;
    let out = repo.init(&["myapp"])?;
    assert_eq!(status(&out), 0, "init failed: {}", String::from_utf8_lossy(&out.stderr));
    let playbook =
        fs::read_to_string(repo.path("playbooks/deploy-myapp.sh")).map_err(|e| e.to_string())?;
    assert!(playbook.contains("# @server api      api"), "default host missing: {playbook}");
    assert!(playbook.contains("# @remote api"), "default host missing from remote steps");
    Ok(())
}

#[test]
fn keys_check_passes_on_matching_sets() -> TestResult<()> {
    let repo = Repo::new("keys-ok")?;
    let svc_dir = repo.path("services/myapp");
    fs::create_dir_all(&svc_dir).map_err(|e| e.to_string())?;
    let (key, _) = encrypted_env(&svc_dir, "api", "API_KEY=x\nDB_PASSWORD=y\n")?;
    // Second host with the same keys, different values.
    let out =
        shellflow().args(["keys", "public", "-i"]).arg(&key).output().map_err(|e| e.to_string())?;
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let plain = svc_dir.join("trade.env");
    fs::write(&plain, "API_KEY=z\nDB_PASSWORD=w\n").map_err(|e| e.to_string())?;
    let out = shellflow()
        .args(["secret", "encrypt", "-r", &pubkey, "-o"])
        .arg(svc_dir.join("trade.env.age"))
        .arg(&plain)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "encrypt failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = shellflow()
        .args(["secret", "keys-check", "-i"])
        .arg(&key)
        .arg(&svc_dir)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(
        status(&out),
        0,
        "matching key sets must pass: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("api: API_KEY DB_PASSWORD"), "per-host listing missing: {stdout}");
    assert!(stdout.contains("trade: API_KEY DB_PASSWORD"), "per-host listing missing: {stdout}");
    assert!(stdout.contains("OK: 2 host(s)"), "summary missing: {stdout}");
    Ok(())
}

#[test]
fn keys_check_fails_on_mismatch() -> TestResult<()> {
    let repo = Repo::new("keys-mismatch")?;
    let svc_dir = repo.path("services/myapp");
    fs::create_dir_all(&svc_dir).map_err(|e| e.to_string())?;
    let (key, _) = encrypted_env(&svc_dir, "api", "API_KEY=x\nDB_PASSWORD=y\n")?;
    let out =
        shellflow().args(["keys", "public", "-i"]).arg(&key).output().map_err(|e| e.to_string())?;
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let plain = svc_dir.join("trade.env");
    fs::write(&plain, "API_KEY=z\n").map_err(|e| e.to_string())?;
    let out = shellflow()
        .args(["secret", "encrypt", "-r", &pubkey, "-o"])
        .arg(svc_dir.join("trade.env.age"))
        .arg(&plain)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "encrypt failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = shellflow()
        .args(["secret", "keys-check", "-i"])
        .arg(&key)
        .arg(&svc_dir)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "a key set mismatch must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("DB_PASSWORD"), "the error must name the differing key: {stderr}");
    Ok(())
}

#[test]
fn keys_check_rejects_a_directory_without_env_files() -> TestResult<()> {
    let repo = Repo::new("keys-empty")?;
    let svc_dir = repo.path("services/myapp");
    fs::create_dir_all(&svc_dir).map_err(|e| e.to_string())?;
    let out = shellflow()
        .args(["secret", "keys-check", "-i", "/nonexistent-key"])
        .arg(&svc_dir)
        .output()
        .map_err(|e| e.to_string())?;
    assert_ne!(status(&out), 0, "an empty service directory must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no *.env.age"), "unclear error: {stderr}");
    Ok(())
}
