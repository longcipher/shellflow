//! Tests for the `cred-env` target-side helper and its tooling:
//! `shellflow emit cred-env` and `shellflow template check`.
//!
//! The helper itself is a bash asset (`assets/cred-env.sh`) embedded into the
//! binary; these tests exercise the *emitted bytes* exactly as a target would
//! run them, against a fake `$CREDENTIALS_DIRECTORY`.

use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

type TestResult<T> = std::result::Result<T, String>;

/// The helper asset as shipped in the repository.
fn asset() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets").join("cred-env.sh")
}

fn shellflow() -> Command {
    // No `--no-color`: global run flags conflict with subcommands
    // (`args_conflicts_with_subcommands`), and these subcommands never color.
    Command::new(env!("CARGO_BIN_EXE_shellflow"))
}

fn status(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// A fake credential directory: one file per credential.
struct Creds {
    dir: PathBuf,
}

impl Creds {
    fn new(name: &str) -> TestResult<Self> {
        let dir =
            std::env::temp_dir().join(format!("shellflow-credenv-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        Ok(Self { dir })
    }

    fn set(&self, key: &str, value: &str) -> TestResult<()> {
        fs::write(self.dir.join(key), value).map_err(|e| e.to_string())
    }
}

impl Drop for Creds {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Run the helper with `bash` against a fake credential directory.
fn run_helper(args: &[&str], creds: Option<&Creds>) -> TestResult<Output> {
    let mut cmd = Command::new("bash");
    cmd.arg(asset());
    cmd.args(args);
    match creds {
        Some(c) => {
            cmd.env("CREDENTIALS_DIRECTORY", &c.dir);
        }
        None => {
            cmd.env_remove("CREDENTIALS_DIRECTORY");
        }
    }
    cmd.output().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Asset integrity
// ---------------------------------------------------------------------------

#[test]
fn asset_is_valid_bash() -> TestResult<()> {
    let out = Command::new("bash").arg("-n").arg(asset()).output().map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "bash -n failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

#[test]
fn emit_prints_the_asset_verbatim() -> TestResult<()> {
    let out = shellflow().args(["emit", "cred-env"]).output().map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "emit failed: {}", String::from_utf8_lossy(&out.stderr));
    let expected = fs::read_to_string(asset()).map_err(|e| e.to_string())?;
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        expected,
        "emitted bytes must match the asset"
    );
    Ok(())
}

#[test]
fn emit_writes_an_executable_file() -> TestResult<()> {
    let dir = std::env::temp_dir().join(format!("shellflow-emit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("cred-env");
    let out = shellflow()
        .args(["emit", "cred-env", "-o"])
        .arg(&path)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "emit -o failed: {}", String::from_utf8_lossy(&out.stderr));
    let mode = fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode();
    assert_eq!(mode & 0o777, 0o755, "emitted helper must be executable, got {mode:o}");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// cred-env exec
// ---------------------------------------------------------------------------

#[test]
fn exec_exports_credentials_and_execs() -> TestResult<()> {
    let creds = Creds::new("exec")?;
    creds.set("API_KEY", "s3cr3t-value")?;
    creds.set("ZENOH_PASSWORD", "p@ss w/ spaces & sym|ols $x")?;
    // A filename that is not a valid variable name must be skipped, not
    // exported (it would be an invalid env assignment).
    creds.set("BAD-NAME", "ignored")?;
    let out = run_helper(&["exec", "printenv", "API_KEY"], Some(&creds))?;
    assert_eq!(status(&out), 0, "exec failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "s3cr3t-value");

    let out = run_helper(&["exec", "printenv", "ZENOH_PASSWORD"], Some(&creds))?;
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "p@ss w/ spaces & sym|ols $x");

    // The invalid name must not have been exported.
    let out = run_helper(&["exec", "printenv", "BAD-NAME"], Some(&creds))?;
    assert_ne!(status(&out), 0, "BAD-NAME must not be exported");
    Ok(())
}

#[test]
fn exec_fails_closed_without_credential_directory() -> TestResult<()> {
    let out = run_helper(&["exec", "true"], None)?;
    assert_ne!(status(&out), 0, "missing CREDENTIALS_DIRECTORY must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CREDENTIALS_DIRECTORY"), "unclear error: {stderr}");
    Ok(())
}

#[test]
fn exec_requires_a_command() -> TestResult<()> {
    let creds = Creds::new("nocmd")?;
    creds.set("A", "1")?;
    let out = run_helper(&["exec"], Some(&creds))?;
    assert_ne!(status(&out), 0);
    Ok(())
}

#[test]
fn unknown_subcommand_is_rejected() -> TestResult<()> {
    let out = run_helper(&["frobnicate"], None)?;
    assert_eq!(status(&out), 2);
    Ok(())
}

// ---------------------------------------------------------------------------
// cred-env render
// ---------------------------------------------------------------------------

/// A template in the shape of a zenoh JSON5 config: braced placeholders plus
/// text that must survive verbatim.
const TEMPLATE: &str = r#"{
  mode: "router",
  listen: { endpoints: ["${ZENOH_LISTEN}"] },
  transport: { auth: { usrpwd: { user: "${ZENOH_USER}", password: "${ZENOH_PASSWORD}" } } },
  // $NOT_A_PLACEHOLDER and ${1BAD} must stay literal
  note: "$NOT_A_PLACEHOLDER ${1BAD}",
}
"#;

#[test]
fn render_substitutes_values_literally() -> TestResult<()> {
    let creds = Creds::new("render")?;
    creds.set("ZENOH_LISTEN", "tcp/10.0.0.7:7447")?;
    creds.set("ZENOH_USER", "op&user")?;
    // A value with every character a sed-based renderer would choke on.
    creds.set("ZENOH_PASSWORD", "p@ss&|$x\\y'z")?;

    let dir = std::env::temp_dir().join(format!("shellflow-render-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    let out_path = dir.join("svc.json5");
    fs::write(&tmpl, TEMPLATE).map_err(|e| e.to_string())?;

    let out = run_helper(
        &["render", tmpl.to_str().expect("utf8 path"), out_path.to_str().expect("utf8 path")],
        Some(&creds),
    )?;
    assert_eq!(status(&out), 0, "render failed: {}", String::from_utf8_lossy(&out.stderr));

    let rendered = fs::read_to_string(&out_path).map_err(|e| e.to_string())?;
    assert!(
        rendered.contains("endpoints: [\"tcp/10.0.0.7:7447\"]"),
        "listen not substituted:\n{rendered}"
    );
    assert!(rendered.contains("user: \"op&user\""), "user not substituted:\n{rendered}");
    assert!(
        rendered.contains("password: \"p@ss&|$x\\y'z\""),
        "password not substituted literally:\n{rendered}"
    );
    // Non-placeholders must survive untouched.
    assert!(rendered.contains("$NOT_A_PLACEHOLDER ${1BAD}"), "literals were mangled:\n{rendered}");
    assert!(!rendered.contains("${ZENOH_"), "a placeholder was left unsubstituted:\n{rendered}");

    // The rendered file holds secrets: owner-only.
    let mode = fs::metadata(&out_path).map_err(|e| e.to_string())?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "rendered file must be 0600, got {mode:o}");

    // No temp files may be left behind.
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".cred-env."))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn render_fails_closed_on_missing_credential() -> TestResult<()> {
    let creds = Creds::new("render-missing")?;
    creds.set("ZENOH_LISTEN", "tcp/10.0.0.7:7447")?;
    // ZENOH_USER / ZENOH_PASSWORD are referenced by the template but absent.

    let dir = std::env::temp_dir().join(format!("shellflow-render-missing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    let out_path = dir.join("svc.json5");
    fs::write(&tmpl, TEMPLATE).map_err(|e| e.to_string())?;

    let out = run_helper(
        &["render", tmpl.to_str().expect("utf8 path"), out_path.to_str().expect("utf8 path")],
        Some(&creds),
    )?;
    assert_ne!(status(&out), 0, "missing credentials must abort the render");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ZENOH_USER"), "error must name the missing key: {stderr}");
    assert!(stderr.contains("ZENOH_PASSWORD"), "error must name the missing key: {stderr}");
    // Nothing may be written when the render aborts.
    assert!(!out_path.exists(), "output file must not be created on failure");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn render_handles_self_referential_and_empty_values() -> TestResult<()> {
    let creds = Creds::new("render-edge")?;
    // A value that itself looks like a placeholder must be inserted verbatim:
    // no re-scanning of substituted text (no loop, no double substitution).
    creds.set("TRICKY", "pre${TRICKY}post")?;
    // An empty credential is valid (the key exists) and renders as empty.
    creds.set("EMPTY", "")?;

    let dir = std::env::temp_dir().join(format!("shellflow-render-edge-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("edge.tmpl");
    let out_path = dir.join("edge.out");
    fs::write(&tmpl, "a=[${TRICKY}]\nb=[${EMPTY}]\n").map_err(|e| e.to_string())?;

    let out = run_helper(
        &["render", tmpl.to_str().expect("utf8 path"), out_path.to_str().expect("utf8 path")],
        Some(&creds),
    )?;
    assert_eq!(status(&out), 0, "render failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        fs::read_to_string(&out_path).map_err(|e| e.to_string())?,
        "a=[pre${TRICKY}post]\nb=[]\n",
        "self-referential and empty values must render verbatim"
    );
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn render_rejects_missing_template_and_bad_usage() -> TestResult<()> {
    let creds = Creds::new("render-bad")?;
    creds.set("A", "1")?;
    let out = run_helper(&["render", "/nonexistent.tmpl", "/tmp/out.json"], Some(&creds))?;
    assert_ne!(status(&out), 0, "unreadable template must fail");

    let out = run_helper(&["render", "only-one-arg"], Some(&creds))?;
    assert_eq!(status(&out), 2, "wrong argument count must be a usage error");
    Ok(())
}

// ---------------------------------------------------------------------------
// template check (needs the full age round-trip through the binary)
// ---------------------------------------------------------------------------

/// Create an identity + encrypted env file through the real CLI; returns
/// `(identity_path, env_age_path, public_key)`.
fn encrypted_env(name: &str, plaintext: &str) -> TestResult<(PathBuf, PathBuf, String)> {
    let dir =
        std::env::temp_dir().join(format!("shellflow-tmplcheck-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let key = dir.join("keys.txt");
    let out = shellflow()
        .args(["keys", "generate", "-o"])
        .arg(&key)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "keys generate failed: {}", String::from_utf8_lossy(&out.stderr));

    let out =
        shellflow().args(["keys", "public", "-i"]).arg(&key).output().map_err(|e| e.to_string())?;
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let plain = dir.join("plain.env");
    fs::write(&plain, plaintext).map_err(|e| e.to_string())?;
    let env_age = dir.join("svc.env.age");
    let out = shellflow()
        .args(["secret", "encrypt", "-r", &pubkey, "-o"])
        .arg(&env_age)
        .arg(&plain)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "secret encrypt failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok((key, env_age, pubkey))
}

#[test]
fn template_check_passes_when_env_covers_template() -> TestResult<()> {
    let (key, env_age, _) = encrypted_env("ok", "ZENOH_USER=u\nZENOH_LISTEN=tcp/1.2.3.4:7447\n")?;
    let tmpl = env_age.parent().expect("parent").join("svc.json5.tmpl");
    fs::write(&tmpl, "user: \"${ZENOH_USER}\"\nlisten: [\"${ZENOH_LISTEN}\"]\n")
        .map_err(|e| e.to_string())?;

    let out = shellflow()
        .args(["template", "check", "-i"])
        .arg(&key)
        .arg(&tmpl)
        .arg(&env_age)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(
        status(&out),
        0,
        "check failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("OK: 2 key(s)"));
    Ok(())
}

#[test]
fn template_check_fails_on_missing_key() -> TestResult<()> {
    let (key, env_age, _) = encrypted_env("missing", "ZENOH_USER=u\n")?;
    let tmpl = env_age.parent().expect("parent").join("svc.json5.tmpl");
    fs::write(&tmpl, "user: \"${ZENOH_USER}\"\npassword: \"${ZENOH_PASSWORD}\"\n")
        .map_err(|e| e.to_string())?;

    let out = shellflow()
        .args(["template", "check", "-i"])
        .arg(&key)
        .arg(&tmpl)
        .arg(&env_age)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "a missing key must fail the check");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ZENOH_PASSWORD"), "error must name the missing key: {stderr}");
    Ok(())
}

#[test]
fn template_check_warns_about_unused_keys() -> TestResult<()> {
    let (key, env_age, _) = encrypted_env("unused", "ZENOH_USER=u\nZENOH_STALE=old\n")?;
    let tmpl = env_age.parent().expect("parent").join("svc.json5.tmpl");
    fs::write(&tmpl, "user: \"${ZENOH_USER}\"\n").map_err(|e| e.to_string())?;

    let out = shellflow()
        .args(["template", "check", "-i"])
        .arg(&key)
        .arg(&tmpl)
        .arg(&env_age)
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "an unused key is a warning, not a failure");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("note: ZENOH_STALE"), "unused key not reported: {stdout}");
    Ok(())
}

#[test]
fn template_check_resolves_identity_from_env() -> TestResult<()> {
    let (key, env_age, _) = encrypted_env("env-identity", "ZENOH_USER=u\n")?;
    let tmpl = env_age.parent().expect("parent").join("svc.json5.tmpl");
    fs::write(&tmpl, "user: \"${ZENOH_USER}\"\n").map_err(|e| e.to_string())?;

    let mut cmd = shellflow();
    cmd.args(["template", "check"]).arg(&tmpl).arg(&env_age);
    cmd.env("SHELLFLOW_AGE_IDENTITY", &key);
    let out = cmd.output().map_err(|e| e.to_string())?;
    assert_eq!(
        status(&out),
        0,
        "identity should resolve from the env var: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(())
}

/// Keep `Path` in scope for the helper signature above.
#[allow(dead_code)]
fn _path_marker(_: &Path) {}

// ---------------------------------------------------------------------------
// cred-env subcommands (the Rust binary on the target)
//
// These mirror the bash-asset suite above: both implementations must keep the
// same semantics, so any behavioral change shows up as a divergence here.
// ---------------------------------------------------------------------------

/// Run `shellflow cred-env …` against a fake credential directory.
fn run_cred_env(args: &[&str], creds: Option<&Creds>) -> TestResult<Output> {
    let mut cmd = shellflow();
    cmd.arg("cred-env").args(args);
    match creds {
        Some(c) => {
            cmd.env("CREDENTIALS_DIRECTORY", &c.dir);
        }
        None => {
            cmd.env_remove("CREDENTIALS_DIRECTORY");
        }
    }
    cmd.output().map_err(|e| e.to_string())
}

#[test]
fn rust_exec_exports_credentials_and_execs() -> TestResult<()> {
    let creds = Creds::new("rust-exec")?;
    creds.set("API_KEY", "s3cr3t-value")?;
    creds.set("ZENOH_PASSWORD", "p@ss w/ spaces & sym|ols $x")?;
    creds.set("BAD-NAME", "ignored")?;
    let out = run_cred_env(&["exec", "printenv", "API_KEY"], Some(&creds))?;
    assert_eq!(status(&out), 0, "exec failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "s3cr3t-value");

    let out = run_cred_env(&["exec", "printenv", "ZENOH_PASSWORD"], Some(&creds))?;
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "p@ss w/ spaces & sym|ols $x");

    let out = run_cred_env(&["exec", "printenv", "BAD-NAME"], Some(&creds))?;
    assert_ne!(status(&out), 0, "BAD-NAME must not be exported");
    Ok(())
}

#[test]
fn rust_exec_passes_flags_through() -> TestResult<()> {
    // `ExecStart=` relies on flags and extra positional args reaching the
    // wrapped program, and on the exported env var being visible to it.
    // `printenv NAME EXTRA` is rejected by both GNU and BSD printenv ("extra
    // operand"), so use `sh -c` with a positional arg to prove passthrough.
    let creds = Creds::new("rust-exec-flags")?;
    creds.set("GREETING", "hello")?;
    let out =
        run_cred_env(&["exec", "sh", "-c", "echo $GREETING:$1", "sh", "extra"], Some(&creds))?;
    assert_eq!(status(&out), 0, "exec failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello:extra");
    Ok(())
}

#[test]
fn rust_exec_propagates_exit_code() -> TestResult<()> {
    let creds = Creds::new("rust-exec-exit")?;
    creds.set("A", "1")?;
    let out = run_cred_env(&["exec", "sh", "-c", "exit 7"], Some(&creds))?;
    assert_eq!(status(&out), 7, "exec must replace the process (exit code propagates)");
    Ok(())
}

#[test]
fn rust_exec_fails_closed_without_credential_directory() -> TestResult<()> {
    let out = run_cred_env(&["exec", "true"], None)?;
    assert_ne!(status(&out), 0, "missing CREDENTIALS_DIRECTORY must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("CREDENTIALS_DIRECTORY"), "unclear error: {stderr}");
    Ok(())
}

#[test]
fn rust_render_substitutes_values_literally() -> TestResult<()> {
    let creds = Creds::new("rust-render")?;
    creds.set("ZENOH_LISTEN", "tcp/10.0.0.1:7447")?;
    creds.set("ZENOH_USER", "op&user")?;
    creds.set("ZENOH_PASSWORD", "p@ss|w$x\"y'z\\q")?;
    // Dedicated template dir: sharing `/tmp/svc.json5.tmpl` across parallel
    // tests races (another test overwrites it with `a: "${A}"`).
    let dir = std::env::temp_dir().join(format!("shellflow-rust-render-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    fs::write(&tmpl, TEMPLATE).map_err(|e| e.to_string())?;
    let out_path = dir.join("rendered.json5");
    let _ = fs::remove_file(&out_path);

    let out = run_cred_env(
        &["render", tmpl.to_str().expect("utf8"), out_path.to_str().expect("utf8")],
        Some(&creds),
    )?;
    assert_eq!(status(&out), 0, "render failed: {}", String::from_utf8_lossy(&out.stderr));
    let rendered = fs::read_to_string(&out_path).map_err(|e| e.to_string())?;
    assert!(rendered.contains("\"tcp/10.0.0.1:7447\""), "listen missing: {rendered}");
    assert!(rendered.contains("user: \"op&user\""), "user missing: {rendered}");
    assert!(
        rendered.contains("password: \"p@ss|w$x\"y'z\\q\""),
        "password not literal: {rendered}"
    );
    assert!(rendered.contains("$NOT_A_PLACEHOLDER ${1BAD}"), "non-placeholders must survive");
    let mode = fs::metadata(&out_path).map_err(|e| e.to_string())?.permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "rendered file must be 0600, got {mode:o}");
    // No temp file may be left behind next to the output.
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".tmp."))
        .collect();
    assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn rust_render_fails_closed_on_missing_credential() -> TestResult<()> {
    let creds = Creds::new("rust-render-missing")?;
    creds.set("ZENOH_LISTEN", "tcp/10.0.0.1:7447")?;
    let dir = std::env::temp_dir().join(format!("shellflow-rust-missing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    fs::write(&tmpl, TEMPLATE).map_err(|e| e.to_string())?;
    let out_path = dir.join("missing.json5");

    let out = run_cred_env(
        &["render", tmpl.to_str().expect("utf8"), out_path.to_str().expect("utf8")],
        Some(&creds),
    )?;
    assert_eq!(status(&out), 1, "a missing credential must fail the render");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ZENOH_USER"), "error must name the missing key: {stderr}");
    assert!(!out_path.exists(), "no output may be written on failure");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn rust_render_fails_closed_without_credential_directory() -> TestResult<()> {
    let dir = std::env::temp_dir().join(format!("shellflow-render-nocreds-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    fs::write(&tmpl, "a: \"${A}\"\n").map_err(|e| e.to_string())?;
    let out = run_cred_env(
        &["render", tmpl.to_str().expect("utf8"), dir.join("out.json5").to_str().expect("utf8")],
        None,
    )?;
    assert_ne!(status(&out), 0, "missing CREDENTIALS_DIRECTORY must fail");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn rust_render_rejects_non_utf8_value() -> TestResult<()> {
    let creds = Creds::new("rust-render-utf8")?;
    fs::write(creds.dir.join("A"), [0x66, 0x6f, 0xff, 0xfe]).map_err(|e| e.to_string())?;
    let dir = std::env::temp_dir().join(format!("shellflow-rust-utf8-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let tmpl = dir.join("svc.json5.tmpl");
    fs::write(&tmpl, "a: \"${A}\"\n").map_err(|e| e.to_string())?;
    let out_path = dir.join("utf8.json5");
    let out = run_cred_env(
        &["render", tmpl.to_str().expect("utf8"), out_path.to_str().expect("utf8")],
        Some(&creds),
    )?;
    assert_ne!(status(&out), 0, "a non-UTF-8 credential cannot be substituted");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("UTF-8"), "unclear error: {stderr}");
    assert!(!out_path.exists(), "no output may be written on failure");
    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// cred-env credstore-install (stubbed sudo / systemd-creds)
// ---------------------------------------------------------------------------

/// A fake `sudo` on `PATH` that records its argv and emulates the three
/// operations `credstore-install` needs (`install -d`, `find -delete`,
/// `chmod`, and `systemd-creds encrypt` reading the secret from stdin).
struct SudoStub {
    bin: PathBuf,
    log: PathBuf,
}

impl SudoStub {
    fn new(name: &str) -> TestResult<Self> {
        let base =
            std::env::temp_dir().join(format!("shellflow-credstore-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let bin = base.join("bin");
        fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
        let log = base.join("sudo.log");
        let script = bin.join("sudo");
        fs::write(
            &script,
            format!(
                r#"#!/usr/bin/env bash
echo "$*" >> "{}"
case "$1" in
  systemd-creds)
    out="${{@: -1}}"
    mkdir -p "$(dirname "$out")" || exit 1
    cat > "$out" || exit 1
    ;;
  install)
    for a in "$@"; do d="$a"; done
    mkdir -p "$d" || exit 1
    ;;
  find)
    dir="$2"
    find "$dir" -mindepth 1 -delete || exit 1
    ;;
esac
exit 0
"#,
                log.display(),
            ),
        )
        .map_err(|e| e.to_string())?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        Ok(Self { bin, log })
    }

    /// A `Command` for `cred-env credstore-install` with the stub on `PATH`.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = shellflow();
        cmd.arg("cred-env").arg("credstore-install").args(args);
        let path = env::var_os("PATH").unwrap_or_default();
        cmd.env("PATH", format!("{}:{}", self.bin.display(), path.to_string_lossy()));
        cmd
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).map(|s| s.to_string()).unwrap_or_default()
    }
}

impl Drop for SudoStub {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.bin.parent().unwrap_or(&self.bin));
    }
}

#[test]
fn credstore_install_seals_every_key() -> TestResult<()> {
    let stub = SudoStub::new("seal")?;
    let store = std::env::temp_dir().join(format!("shellflow-store-seal-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    let store_dir = store.join("zenoh");
    let out = stub
        .command(&["zenoh", "--store-dir", store_dir.to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "ZENOH_LISTEN ZENOH_USER ZENOH_PASSWORD")
        .env("ZENOH_LISTEN", "tcp/10.0.0.1:7447")
        .env("ZENOH_USER", "op&user")
        .env("ZENOH_PASSWORD", "p@ss|w")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "install failed: {}", String::from_utf8_lossy(&out.stderr));

    for (key, value) in [
        ("ZENOH_LISTEN", "tcp/10.0.0.1:7447"),
        ("ZENOH_USER", "op&user"),
        ("ZENOH_PASSWORD", "p@ss|w"),
    ] {
        let sealed = fs::read(store.join("zenoh").join(key)).map_err(|e| e.to_string())?;
        assert_eq!(String::from_utf8_lossy(&sealed), value, "sealed value mismatch for {key}");
    }
    // Values must never appear in argv (the sudo log records argv only).
    let log = stub.log();
    assert!(log.contains("--name ZENOH_USER"), "cred name missing from systemd-creds call: {log}");
    assert!(!log.contains("p@ss|w"), "secret leaked into argv: {log}");
    assert!(!log.contains("op&user"), "secret leaked into argv: {log}");
    assert!(log.contains("find"), "the store must be cleared first: {log}");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_clears_the_store_first() -> TestResult<()> {
    let stub = SudoStub::new("clear")?;
    let store = std::env::temp_dir().join(format!("shellflow-store-clear-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    fs::create_dir_all(store.join("zenoh")).map_err(|e| e.to_string())?;
    fs::write(store.join("zenoh").join("STALE_KEY"), "old").map_err(|e| e.to_string())?;

    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "FRESH_KEY")
        .env("FRESH_KEY", "v")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 0, "install failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!store.join("zenoh").join("STALE_KEY").exists(), "stale credential must be cleared");
    assert!(store.join("zenoh").join("FRESH_KEY").exists(), "fresh credential must be written");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_fails_closed_on_empty_value() -> TestResult<()> {
    let stub = SudoStub::new("empty")?;
    let store = std::env::temp_dir().join(format!("shellflow-store-empty-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "A B")
        .env("A", "")
        .env("B", "v")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "an empty credential must abort");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("`A` is empty"), "unclear error: {stderr}");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_fails_closed_on_unset_key_list() -> TestResult<()> {
    let stub = SudoStub::new("nolist")?;
    let store = std::env::temp_dir().join(format!("shellflow-store-nolist-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env_remove("LT_SECRET_KEYS")
        .env("A", "1")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "an unset key list must abort (the store must not be wiped)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("LT_SECRET_KEYS"), "unclear error: {stderr}");
    assert!(!store.exists(), "the store must not be touched");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_fails_closed_on_missing_key() -> TestResult<()> {
    let stub = SudoStub::new("missingkey")?;
    let store =
        std::env::temp_dir().join(format!("shellflow-store-missing-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "PRESENT ABSENT")
        .env("PRESENT", "v")
        .env_remove("ABSENT")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "a missing credential must abort");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("ABSENT"), "error must name the key: {stderr}");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_rejects_invalid_key_name() -> TestResult<()> {
    let stub = SudoStub::new("badkey")?;
    let store = std::env::temp_dir().join(format!("shellflow-store-badkey-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "BAD-NAME")
        .env("BAD-NAME", "v")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "an invalid key name must abort");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("BAD-NAME"), "unclear error: {stderr}");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}

#[test]
fn credstore_install_rejects_unsafe_service_name() -> TestResult<()> {
    let stub = SudoStub::new("badsvc")?;
    let out = stub
        .command(&["../evil"])
        .env("LT_SECRET_KEYS", "A")
        .env("A", "1")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(status(&out), 1, "an unsafe service name must abort");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unsafe service name"), "unclear error: {stderr}");
    assert!(stub.log().is_empty(), "nothing must run for an invalid service name");
    Ok(())
}

#[test]
fn credstore_install_empty_list_clears_the_store() -> TestResult<()> {
    // A set-but-empty list is an explicit "this service has no credentials":
    // the store is cleared and the command succeeds.
    let stub = SudoStub::new("emptylist")?;
    let store =
        std::env::temp_dir().join(format!("shellflow-store-emptylist-{}", std::process::id()));
    let _ = fs::remove_dir_all(&store);
    fs::create_dir_all(store.join("zenoh")).map_err(|e| e.to_string())?;
    fs::write(store.join("zenoh").join("OLD"), "v").map_err(|e| e.to_string())?;
    let out = stub
        .command(&["zenoh", "--store-dir", store.join("zenoh").to_str().expect("utf8")])
        .env("LT_SECRET_KEYS", "")
        .output()
        .map_err(|e| e.to_string())?;
    assert_eq!(
        status(&out),
        0,
        "an empty list clears the store: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!store.join("zenoh").join("OLD").exists(), "the store must be cleared");
    let _ = fs::remove_dir_all(&store);
    Ok(())
}
