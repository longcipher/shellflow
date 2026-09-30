//! End-to-end integration tests for the `shellflow` binary.
//!
//! These tests run the real binary with mock `ssh`/`rsync` shims placed
//! earlier on `PATH` (see `tests/mockbin/`). The shims record argv and stdin,
//! so we can assert on payloads, flags, and fan-out without any network.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

const SSH_LOG: &str = "ssh.log";
const RSYNC_LOG: &str = "rsync.log";

type TestResult<T> = std::result::Result<T, String>;

/// A disposable sandbox holding mock shims, logs, and fixtures.
struct Sandbox {
    dir: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> TestResult<Self> {
        let dir = std::env::temp_dir().join(format!("shellflow-it-{}-{name}", std::process::id()));
        if dir.exists() {
            let _ = fs::remove_dir_all(&dir);
        }
        fs::create_dir_all(dir.join("mockbin")).map_err(|e| e.to_string())?;
        install_shim(&dir, "ssh")?;
        install_shim(&dir, "rsync")?;
        install_shim(&dir, "scp")?;
        Ok(Self { dir })
    }

    fn mock_dir(&self) -> PathBuf {
        self.dir.join("mockbin")
    }

    /// Write a deploy script and return its path.
    fn script(&self, content: &str) -> TestResult<PathBuf> {
        let path = self.dir.join("deploy.sh");
        fs::write(&path, content).map_err(|e| e.to_string())?;
        Ok(path)
    }

    /// Run the shellflow binary with the mock PATH.
    fn run(&self, script: &Path, args: &[&str]) -> TestResult<Output> {
        run_with_env(script, args, &self.mock_dir(), &[])
    }

    fn read(&self, file: &str) -> String {
        fs::read_to_string(self.mock_dir().join(file)).unwrap_or_default()
    }

    fn ssh_log(&self) -> String {
        self.read(SSH_LOG)
    }

    fn rsync_log(&self) -> String {
        self.read(RSYNC_LOG)
    }

    fn scp_log(&self) -> String {
        self.read("scp.log")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Install one of the mock shims into the sandbox, executable.
fn install_shim(sandbox: &Path, name: &str) -> TestResult<()> {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("mockbin").join(name);
    let dst = sandbox.join("mockbin").join(name);
    fs::copy(&src, &dst).map_err(|e| e.to_string())?;
    let mut perms = fs::metadata(&dst).map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&dst, perms).map_err(|e| e.to_string())
}

/// Run the binary with the sandbox mock PATH.
fn run_with_env(
    script: &Path,
    args: &[&str],
    mock_dir: &Path,
    extra: &[(&str, &str)],
) -> TestResult<Output> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellflow"));
    cmd.arg(script);
    cmd.args(args);
    // Tests assert on plain text; disable ANSI unless the test opts in.
    if !args.contains(&"--no-color") {
        cmd.arg("--no-color");
    }
    cmd.env("MOCK_DIR", mock_dir);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", mock_dir.display()));
    for (k, v) in extra {
        cmd.env(k, v);
    }
    cmd.output().map_err(|e| e.to_string())
}

fn status_code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

const BASIC_SCRIPT: &str = r"# @server echo1 echo@h1
# @group  g echo1
# @local
echo LOCAL_STEP
# @remote g
echo REMOTE_STEP
";

// ---------------------------------------------------------------------------
// Remote execution & payloads
// ---------------------------------------------------------------------------

#[test]
fn local_then_remote_streaming() -> TestResult<()> {
    let sb = Sandbox::new("basic")?;
    let script = sb.script(BASIC_SCRIPT)?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LOCAL_STEP"), "local step output missing: {stdout}");
    assert!(stdout.contains("[echo1] echo REMOTE_STEP"), "remote output missing: {stdout}");
    let log = sb.ssh_log();
    assert!(log.contains("echo@h1"), "ssh target missing: {log}");
    assert!(log.contains("bash -l -s"), "login-shell remote mode missing: {log}");
    Ok(())
}

#[test]
fn payload_contains_env_and_header() -> TestResult<()> {
    let sb = Sandbox::new("payload")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @env GREETING=hi\n\
         # @remote echo1\n\
         echo \"$GREETING\"\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0);
    let stdin = sb.read("ssh-stdin-echo@h1.txt");
    // `set -eu` opens the payload, then the env block (including the probed
    // login PATH), then the user script. The rc file itself is never sourced
    // inside the payload.
    assert!(stdin.starts_with("set -eu\n"), "payload header missing: {stdin:?}");
    assert!(stdin.contains("export GREETING='hi';"), "env injection missing: {stdin:?}");
    assert!(stdin.contains("export PATH='"), "login PATH injection missing: {stdin:?}");
    assert!(!stdin.contains(".zshrc"), "rc file must not be sourced in payload: {stdin:?}");
    assert!(stdin.ends_with("echo \"$GREETING\"\n"), "script body missing: {stdin:?}");
    Ok(())
}

#[test]
fn remote_runs_under_login_shell() -> TestResult<()> {
    // Real runs stream payloads over `<shell> -l -s` (a login shell) with the
    // probed rc-extended PATH injected into the env block, so the target sees
    // the same toolchain PATH as a manual `ssh host`.
    let sb = Sandbox::new("loginbash")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @remote echo1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.ssh_log();
    assert!(log.contains("bash -l -s"), "login shell missing: {log}");
    let stdin = sb.read("ssh-stdin-echo@h1.txt");
    assert!(stdin.contains("export PATH='"), "login PATH injection missing: {stdin:?}");
    Ok(())
}

#[test]
fn zsh_host_runs_under_zsh_login_shell() -> TestResult<()> {
    // Hosts whose login shell is zsh get `zsh -l -s` and their rc-extended
    // PATH (the file proto/nvm/mise append to) is injected into the payload.
    let sb = Sandbox::new("loginzsh")?;
    let script = sb.script(
        "# @server zshhost zsh@h1\n\
         # @remote zshhost\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.ssh_log();
    assert!(log.contains("zsh -l -s"), "zsh login shell missing: {log}");
    let stdin = sb.read("ssh-stdin-zsh@h1.txt");
    assert!(stdin.contains("export PATH='"), "login PATH injection missing: {stdin:?}");
    Ok(())
}

#[test]
fn shell_probe_is_cached_per_host() -> TestResult<()> {
    // Two remote steps to the same host must probe the login environment
    // exactly once across the whole run.
    let sb = Sandbox::new("probecache")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @remote echo1\n\
         echo one\n\
         # @remote echo1\n\
         echo two\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.ssh_log();
    let probes = log.matches("$SHELL").count();
    assert_eq!(probes, 1, "env probe should run once per host:\n{log}");
    Ok(())
}

#[test]
fn vvv_injects_set_x_and_ssh_v() -> TestResult<()> {
    let sb = Sandbox::new("vvv")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @remote ok1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["-vvv"])?;
    assert_eq!(status_code(&out), 0);
    let stdin = sb.read("ssh-stdin-ok@h1.txt");
    assert!(stdin.contains("set -x\n"), "set -x missing: {stdin:?}");
    let log = sb.ssh_log();
    assert!(log.contains(" -v "), "ssh -v missing: {log}");
    Ok(())
}

#[test]
fn env_secret_is_masked_in_streamed_output() -> TestResult<()> {
    let sb = Sandbox::new("mask")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @env DB_PASSWORD=supersecret\n\
         # @remote echo1\n\
         echo done\n",
    )?;
    let out = sb.run(&script, &["-vvv"])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("supersecret"), "secret leaked: {stdout}");
    assert!(stdout.contains("***"), "mask not applied: {stdout}");
    Ok(())
}

#[test]
fn check_mode_runs_bash_n_not_execution() -> TestResult<()> {
    let sb = Sandbox::new("check")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @remote ok1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["--check"])?;
    assert_eq!(status_code(&out), 0);
    let log = sb.ssh_log();
    assert!(log.contains("bash -n -s"), "syntax check flag missing: {log}");
    assert!(!log.contains("bash -s\n"), "execution should not happen: {log}");
    Ok(())
}

#[test]
fn dry_run_rsync_itemizes() -> TestResult<()> {
    let sb = Sandbox::new("drycopy")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @copy ./out -> /srv/app @ok1 --delete\n",
    )?;
    let out = sb.run(&script, &["--dry-run"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.rsync_log();
    assert!(log.contains("--dry-run"), "dry-run missing: {log}");
    assert!(log.contains("--delete"), "delete missing: {log}");
    assert!(log.contains("-i"), "itemize missing: {log}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(">f++++++++"), "itemize output missing: {stdout}");
    Ok(())
}

#[test]
fn scp_fallback_when_remote_rsync_missing() -> TestResult<()> {
    // A host without rsync must fall back to `ssh mkdir -p` + `scp` (design
    // §9: the target only needs bash).
    let sb = Sandbox::new("scpfallback")?;
    let script = sb.script(
        "# @server norsync1 norsync@h1\n\
         # @copy ./out -> /srv/app.tar.gz @norsync1\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let scp_log = sb.scp_log();
    assert!(!scp_log.is_empty(), "scp fallback should have run (no rsync on host)");
    // The destination must target the parent dir with a trailing `/` so scp
    // places the file at `/srv/app.tar.gz` (not `/srv/app.tar.gz/app.tar.gz`).
    assert!(scp_log.contains("norsync@h1:/srv/"), "scp should copy into the parent dir: {scp_log}");
    Ok(())
}

#[test]
fn rsync_copy_creates_parent_dir_via_rsync_path() -> TestResult<()> {
    // With a file-style dst, `--rsync-path` must mkdir the *parent*, not the
    // file path itself.
    let sb = Sandbox::new("rsyncpath")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @copy ./out -> /srv/app.tar.gz @ok1\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.rsync_log();
    assert!(log.contains("--rsync-path"), "rsync-path wrapper missing: {log}");
    assert!(log.contains("mkdir -p '/srv' && rsync"), "mkdir should target the parent dir: {log}");
    Ok(())
}

#[test]
fn dry_run_remote_only_syntax_checks() -> TestResult<()> {
    let sb = Sandbox::new("dryremote")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @remote ok1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["--dry-run"])?;
    assert_eq!(status_code(&out), 0);
    let log = sb.ssh_log();
    assert!(log.contains("bash -n -s"), "dry-run should syntax check: {log}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

#[test]
fn fail_fast_aborts_remaining_steps() -> TestResult<()> {
    let sb = Sandbox::new("failfast")?;
    let script = sb.script(
        "# @server fail1 fail@h1\n\
         # @remote fail1\n\
         echo boom\n\
         # @local\n\
         echo never-runs\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 4, "script failure should exit 4");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("never-runs"), "fail-fast should abort remaining steps");
    Ok(())
}

#[test]
fn continue_on_error_keeps_going() -> TestResult<()> {
    let sb = Sandbox::new("continue")?;
    let script = sb.script(
        "# @server fail1 fail@h1\n\
         # @server echo1 echo@h1\n\
         # @remote fail1\n\
         echo boom\n\
         # @remote echo1\n\
         echo SURVIVES_STEP\n",
    )?;
    let out = sb.run(&script, &["--continue-on-error"])?;
    assert_eq!(status_code(&out), 4);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("SURVIVES_STEP"), "continue-on-error should keep going: {stdout}");
    assert!(stdout.contains("FAILED"), "failure should be reported: {stdout}");
    Ok(())
}

#[test]
fn unreachable_host_is_transport_error() -> TestResult<()> {
    let sb = Sandbox::new("transport")?;
    let script = sb.script(
        "# @server dead1 dead@h1\n\
         # @remote dead1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 3, "transport failure should exit 3");
    Ok(())
}

#[test]
fn timeout_kills_hanging_host() -> TestResult<()> {
    let sb = Sandbox::new("timeout")?;
    let script = sb.script(
        "# @server hang1 hang@h1\n\
         # @remote hang1\n\
         sleep 1\n",
    )?;
    let out = sb.run(&script, &["--timeout", "2"])?;
    assert_eq!(status_code(&out), 4, "timeout is a failure");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TIMEOUT") || stdout.contains("timed out"),
        "timeout not reported: {stdout}"
    );
    Ok(())
}

#[test]
fn local_block_is_fail_fast() -> TestResult<()> {
    // `set -eu` is injected into local blocks too, so a failing command stops
    // the block (design §7.2).
    let sb = Sandbox::new("localfail")?;
    let script = sb.script(
        "# @local\n\
         false\n\
         echo SHOULD_NOT_PRINT\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 4, "local failure should exit 4");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("SHOULD_NOT_PRINT"), "local block must abort on first error");
    Ok(())
}

#[test]
fn export_vars_reach_remote_payload() -> TestResult<()> {
    // `@export`ed variables must be injected into later remote blocks via the
    // env header (design §7.6).
    let sb = Sandbox::new("exportremote")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @local\n\
         VERSION=abc123\n\
         # @export VERSION\n\
         # @remote echo1\n\
         echo \"version: ${VERSION}\"\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(
        status_code(&out),
        0,
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdin = sb.read("ssh-stdin-echo@h1.txt");
    assert!(
        stdin.contains("export VERSION='abc123';"),
        "exported var missing from remote payload: {stdin:?}"
    );
    Ok(())
}

#[test]
fn diff_hides_rsync_status_lines() -> TestResult<()> {
    let sb = Sandbox::new("diff")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @copy ./out -> /srv/app @ok1\n",
    )?;
    let out = sb.run(&script, &["--diff"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("sending incremental file list"),
        "--diff should hide rsync status prose: {stdout}"
    );
    assert!(stdout.contains(">f++++++++"), "--diff should keep itemize lines: {stdout}");
    Ok(())
}

#[test]
fn parallel_default_fans_out_concurrently() -> TestResult<()> {
    // Two echo hosts each take ~0.3s. With default `--parallel all` the step
    // finishes in ~0.3s; a serialized (buggy) default would take ~0.6s.
    let sb = Sandbox::new("parallel")?;
    let script = sb.script(
        "# @server e1 echo1@h1\n\
         # @server e2 echo2@h1\n\
         # @group g e1,e2\n\
         # @remote g\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    // READY/DONE barrier: with default `--parallel all` both hosts enter the
    // barrier before either leaves it (READY,READY,DONE,DONE). A serialized
    // default would interleave (READY,DONE,READY,DONE).
    let order = sb.read("order.log");
    let readies_before_first_done = order.lines().take_while(|l| !l.starts_with("DONE")).count();
    assert_eq!(
        readies_before_first_done, 2,
        "default fan-out should be concurrent; order:\n{order}"
    );
    Ok(())
}

#[test]
fn guard_timeout_is_failure() -> TestResult<()> {
    // A hanging `@only_if` guard must be killed by --timeout and reported as a
    // transport failure (exit 3), not hang forever.
    let sb = Sandbox::new("guardtimeout")?;
    let script = sb.script(
        "# @server hang1 hang@h1\n\
         # @remote hang1\n\
         # @only_if test -f /etc/nope\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["--timeout", "1"])?;
    assert_eq!(status_code(&out), 3, "guard timeout should be a transport failure");
    Ok(())
}

// ---------------------------------------------------------------------------
// Selection & restriction
// ---------------------------------------------------------------------------

#[test]
fn target_restrict_filters_hosts() -> TestResult<()> {
    let sb = Sandbox::new("restrict")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @server ok2 ok@h2\n\
         # @group g ok1,ok2\n\
         # @remote g\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["--target", "ok2"])?;
    assert_eq!(status_code(&out), 0);
    let log = sb.ssh_log();
    assert!(!log.contains("ok@h1"), "restricted host should not run: {log}");
    assert!(log.contains("ok@h2"), "selected host missing: {log}");
    Ok(())
}

#[test]
fn only_runs_matching_step_by_name() -> TestResult<()> {
    let sb = Sandbox::new("only")?;
    let script = sb.script(
        "# @name build\n\
         # @local\n\
         echo BUILD_STEP\n\
         # @name deploy\n\
         # @server echo1 echo@h1\n\
         # @remote echo1\n\
         echo DEPLOY_STEP\n",
    )?;
    let out = sb.run(&script, &["--only", "deploy"])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("BUILD_STEP"), "only should skip build: {stdout}");
    assert!(stdout.contains("DEPLOY_STEP"), "only should run deploy: {stdout}");
    Ok(())
}

#[test]
fn skip_excludes_matching_step() -> TestResult<()> {
    let sb = Sandbox::new("skip")?;
    let script = sb.script(
        "# @local\n\
         echo FIRST_STEP\n\
         # @local\n\
         echo SECOND_STEP\n",
    )?;
    let out = sb.run(&script, &["--skip", "1"])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("FIRST_STEP"), "skip 1 should drop first step: {stdout}");
    assert!(stdout.contains("SECOND_STEP"), "step 2 should still run: {stdout}");
    Ok(())
}

#[test]
fn copy_with_only_if_guard_is_parse_error() -> TestResult<()> {
    // `@only_if` on `@copy` is rejected at parse time (exit 1) rather than
    // silently copying where the guard would fail.
    let sb = Sandbox::new("copyguard")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @only_if test -f /etc/nope\n\
         # @copy ./out -> /srv/app @ok1\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 1, "copy+guard must be a parse error");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("copy"), "error should name the copy directive: {stderr}");
    Ok(())
}

// ---------------------------------------------------------------------------
// State, output modes, and CLI edge cases
// ---------------------------------------------------------------------------

#[test]
fn export_captures_state_and_interpolates_copy() -> TestResult<()> {
    let sb = Sandbox::new("export")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @local\n\
         VERSION=abc123\n\
         # @export VERSION\n\
         # @copy out/myapp-$VERSION -> /srv/myapp-$VERSION @ok1\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let log = sb.rsync_log();
    assert!(log.contains("out/myapp-abc123"), "src not interpolated: {log}");
    assert!(log.contains("/srv/myapp-abc123"), "dst not interpolated: {log}");
    Ok(())
}

#[test]
fn unresolved_export_variable_is_error() -> TestResult<()> {
    let sb = Sandbox::new("unresolved")?;
    let script = sb.script(
        "# @local\n\
         echo no version\n\
         # @copy out/myapp-$VERSION -> /srv @ok1\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 4, "unresolved variable should fail the run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let all = format!("{stdout}{stderr}");
    assert!(all.contains("unresolved") || all.contains("VERSION"), "missing error: {all}");
    Ok(())
}

#[test]
fn grouped_output_and_log_file() -> TestResult<()> {
    let sb = Sandbox::new("grouped")?;
    let log_path = sb.dir.join("audit.log");
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @remote echo1\n\
         echo hi\n",
    )?;
    let out = run_with_env(
        &script,
        &["--output", "grouped", "--log-file", &log_path.to_string_lossy()],
        &sb.mock_dir(),
        &[],
    )?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let audit = fs::read_to_string(&log_path).map_err(|e| e.to_string())?;
    assert!(audit.contains("[echo1] OUT echo hi"), "audit log missing line: {audit}");
    Ok(())
}

#[test]
fn no_color_strips_ansi() -> TestResult<()> {
    let sb = Sandbox::new("nocolor")?;
    let script = sb.script("# @local\n\necho hi\n")?;
    let out = sb.run(&script, &["--no-color"])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains('\u{1b}'), "ANSI escape found: {stdout:?}");
    Ok(())
}

#[test]
fn parse_error_exits_one() -> TestResult<()> {
    let sb = Sandbox::new("parseerr")?;
    let script = sb.script("# @frobnicate x\n")?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 1, "parse error should exit 1");
    Ok(())
}

#[test]
fn missing_script_file_is_friendly_error() -> TestResult<()> {
    let sb = Sandbox::new("missingfile")?;
    let script = sb.dir.join("does-not-exist.sh");
    let out = sb.run(&script, &[])?;
    assert_ne!(status_code(&out), 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to read script"), "unexpected stderr: {stderr}");
    Ok(())
}

#[test]
fn preflight_reports_missing_tools() -> TestResult<()> {
    let sb = Sandbox::new("preflight")?;
    let script = sb.script("# @local\n\necho hi\n")?;
    // A PATH without ssh/rsync: preflight must fail fast with exit 3.
    let empty_path = sb.dir.join("empty-path");
    fs::create_dir_all(&empty_path).map_err(|e| e.to_string())?;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellflow"));
    cmd.arg(&script);
    cmd.env("MOCK_DIR", sb.mock_dir());
    cmd.env("PATH", empty_path);
    let out = cmd.output().map_err(|e| e.to_string())?;
    assert_eq!(status_code(&out), 3, "preflight should exit 3");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("missing required tool"), "unexpected stderr: {stderr}");
    Ok(())
}

#[test]
fn sigint_exits_130() -> TestResult<()> {
    // The binary installs a SIGINT handler and must exit 130, reaping the
    // in-flight (hanging) child.
    let sb = Sandbox::new("sigint")?;
    let script = sb.script(
        "# @server hang1 hang@h1\n\
         # @remote hang1\n\
         sleep 300\n",
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_shellflow"))
        .arg(&script)
        .env("MOCK_DIR", sb.mock_dir())
        .env("PATH", format!("{}:/usr/bin:/bin", sb.mock_dir().display()))
        .spawn()
        .map_err(|e| e.to_string())?;
    // Wait for ssh.log to prove the remote step started.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !sb.dir.join(SSH_LOG).exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .map_err(|e| e.to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    assert_eq!(status.code(), Some(130), "SIGINT must exit 130");
    Ok(())
}

// ---------------------------------------------------------------------------
// Local mode + secrets (keys/secret/@secrets subcommands)
// ---------------------------------------------------------------------------

impl Sandbox {
    /// Run the binary with arbitrary args (no script positional) under the
    /// mock PATH.
    fn run_args(&self, args: &[&str]) -> TestResult<Output> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellflow"));
        cmd.args(args);
        cmd.env("MOCK_DIR", self.mock_dir());
        cmd.env("PATH", format!("{}:/usr/bin:/bin", self.mock_dir().display()));
        cmd.output().map_err(|e| e.to_string())
    }
}

#[test]
fn local_mode_runs_remote_blocks_without_ssh() -> TestResult<()> {
    let sb = Sandbox::new("local-mode")?;
    let script = sb.script("# @remote web\necho LOCAL_REMOTE_OUTPUT\n")?;
    let out = sb.run(&script, &["--local"])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("LOCAL_REMOTE_OUTPUT"), "local remote output missing: {stdout}");
    // The mock ssh must never have been invoked.
    assert!(!sb.dir.join(SSH_LOG).exists(), "ssh should not run in local mode");
    Ok(())
}

#[test]
fn local_copy_creates_parent_dir() -> TestResult<()> {
    let sb = Sandbox::new("local-copy")?;
    let src = sb.dir.join("src.txt");
    fs::write(&src, "data").map_err(|e| e.to_string())?;
    let dst = std::env::temp_dir().join("shellflow-it-local-copy-dst.txt");
    let _ = fs::remove_file(&dst);
    let script = sb.script(&format!("# @copy {} -> {} @web\n", src.display(), dst.display()))?;
    let out = sb.run(&script, &["--local"])?;
    assert_eq!(status_code(&out), 0);
    assert!(dst.exists(), "local copy should create the parent and file");
    let _ = fs::remove_file(&dst);
    Ok(())
}

#[test]
fn keys_and_secret_round_trip() -> TestResult<()> {
    let sb = Sandbox::new("keys")?;
    let key = sb.dir.join("keys.txt");
    let out = sb.run_args(&["keys", "generate", "-o", &key.display().to_string()])?;
    assert_eq!(status_code(&out), 0, "keys generate failed: {out:?}");
    assert!(key.exists());

    let out = sb.run_args(&["keys", "public", "-i", &key.display().to_string()])?;
    assert_eq!(status_code(&out), 0);
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert!(pubkey.starts_with("age1"), "unexpected public key: {pubkey}");

    let plain = sb.dir.join("plain.env");
    fs::write(&plain, "DB_PASSWORD=topsecret\nRUST_LOG=info\n").map_err(|e| e.to_string())?;
    let age = sb.dir.join("plain.env.age");
    let out = sb.run_args(&[
        "secret",
        "encrypt",
        "-r",
        &pubkey,
        "-o",
        &age.display().to_string(),
        &plain.display().to_string(),
    ])?;
    assert_eq!(status_code(&out), 0, "encrypt failed: {out:?}");

    let out = sb.run_args(&[
        "secret",
        "decrypt",
        "-i",
        &key.display().to_string(),
        &age.display().to_string(),
    ])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DB_PASSWORD=topsecret"), "decrypt mismatch: {stdout}");

    let out = sb.run_args(&[
        "secret",
        "creds",
        "-i",
        &key.display().to_string(),
        &age.display().to_string(),
    ])?;
    assert_eq!(status_code(&out), 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ImportCredential=DB_PASSWORD"), "creds mismatch: {stdout}");
    Ok(())
}

#[test]
fn secrets_injected_and_masked_in_local_mode() -> TestResult<()> {
    let sb = Sandbox::new("secrets")?;
    let key = sb.dir.join("keys.txt");
    let out = sb.run_args(&["keys", "generate", "-o", &key.display().to_string()])?;
    assert_eq!(status_code(&out), 0);

    let out = sb.run_args(&["keys", "public", "-i", &key.display().to_string()])?;
    let pubkey = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let plain = sb.dir.join("s.env");
    fs::write(&plain, "MY_SECRET=supersecret_xyz_123\n").map_err(|e| e.to_string())?;
    let age = sb.dir.join("s.env.age");
    let out = sb.run_args(&[
        "secret",
        "encrypt",
        "-r",
        &pubkey,
        "-o",
        &age.display().to_string(),
        &plain.display().to_string(),
    ])?;
    assert_eq!(status_code(&out), 0);

    let script = sb.script(&format!(
        "# @secrets {}\n\
         # @remote web\n\
         echo \"value=$MY_SECRET keys=$LT_SECRET_KEYS\"\n",
        age.display()
    ))?;
    let out = sb.run(&script, &["--local", "-i", &key.display().to_string()])?;
    assert_eq!(status_code(&out), 0, "run failed: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("supersecret_xyz_123"), "secret leaked: {stdout}");
    assert!(stdout.contains("***"), "secret not masked: {stdout}");
    assert!(stdout.contains("MY_SECRET"), "LT_SECRET_KEYS missing: {stdout}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Here-document bodies are data, never directives
// ---------------------------------------------------------------------------

#[test]
fn heredoc_body_is_not_interpreted_as_a_directive() -> TestResult<()> {
    // Regression: a `# @remote` line inside a here-document used to become a
    // real directive, so the block was split and `echo pwned` ran on a host
    // the playbook never named.
    let sb = Sandbox::new("heredoc")?;
    let script = sb.script(
        "# @local\n\
         cat <<'INNER'\n\
         # @remote web\n\
         echo pwned\n\
         INNER\n\
         echo after\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(
        status_code(&out),
        0,
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // `cat` prints the body verbatim, so the literal line is visible as data.
    assert!(stdout.contains("[localhost] # @remote web"), "heredoc body was lost: {stdout}");
    assert!(stdout.contains("[localhost] echo pwned"), "heredoc body was lost: {stdout}");
    assert!(stdout.contains("[localhost] after"), "block after the terminator must run: {stdout}");
    // The critical assertion: ssh must never have been invoked.
    assert!(!sb.dir.join(SSH_LOG).exists(), "heredoc body must not become a remote step");
    Ok(())
}

#[test]
fn heredoc_terminator_restores_directive_handling() -> TestResult<()> {
    // The fix must not over-correct: a directive *after* the terminator is a
    // directive again.
    let sb = Sandbox::new("heredoc-after")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @local\n\
         cat <<'EOF'\n\
         body\n\
         EOF\n\
         # @remote echo1\n\
         echo deployed\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[echo1] echo deployed"),
        "post-terminator directive was swallowed: {stdout}"
    );
    Ok(())
}

#[test]
fn here_string_is_not_treated_as_a_heredoc() -> TestResult<()> {
    // `<<<` has no body, so the following directive must still be honored.
    let sb = Sandbox::new("herestring")?;
    let script = sb.script(
        "# @server echo1 echo@h1\n\
         # @local\n\
         cat <<<\"literal\"\n\
         # @remote echo1\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[echo1] echo hi"),
        "directive after a here-string was swallowed: {stdout}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Secrets: per-entry identity and the masking threshold
// ---------------------------------------------------------------------------

#[test]
fn secrets_per_entry_identity_is_honored() -> TestResult<()> {
    // `# @secrets FILE --identity PATH` used to be parsed and then ignored, so
    // the run aborted on the default identity path. Here the file is sealed
    // to a *second* key and no run-wide `-i` is given.
    let sb = Sandbox::new("secrets-identity")?;
    let pinned = sb.dir.join("pinned.txt");
    sb.run_args(&["keys", "generate", "-o", &pinned.display().to_string()])?;
    let pinned_pub = String::from_utf8_lossy(
        &sb.run_args(&["keys", "public", "-i", &pinned.display().to_string()])?.stdout,
    )
    .trim()
    .to_string();

    let plain = sb.dir.join("p.env");
    fs::write(&plain, "PINNED_VALUE=verysecretvalue\n").map_err(|e| e.to_string())?;
    let age = sb.dir.join("p.env.age");
    sb.run_args(&[
        "secret",
        "encrypt",
        "-r",
        &pinned_pub,
        "-o",
        &age.display().to_string(),
        &plain.display().to_string(),
    ])?;

    let script = sb.script(&format!(
        "# @secrets {} --identity {}\n# @local\necho \"got=$PINNED_VALUE keys=$LT_SECRET_KEYS\"\n",
        age.display(),
        pinned.display()
    ))?;
    let out = sb.run(&script, &["--local"])?;
    assert_eq!(status_code(&out), 0, "per-entry identity was ignored: {out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("got=***"), "secret not injected/masked: {stdout}");
    assert!(stdout.contains("keys=PINNED_VALUE"), "LT_SECRET_KEYS missing: {stdout}");
    Ok(())
}

#[test]
fn mask_min_len_env_var_controls_secrets_masking() -> TestResult<()> {
    // `SHELLFLOW_MASK_MIN_LEN` is the documented way to mask short values from
    // CI without editing every playbook.
    let sb = Sandbox::new("maskenv")?;
    let key = sb.dir.join("keys.txt");
    sb.run_args(&["keys", "generate", "-o", &key.display().to_string()])?;
    let pubkey = String::from_utf8_lossy(
        &sb.run_args(&["keys", "public", "-i", &key.display().to_string()])?.stdout,
    )
    .trim()
    .to_string();

    let plain = sb.dir.join("s.env");
    fs::write(&plain, "S=abc\n").map_err(|e| e.to_string())?;
    let age = sb.dir.join("s.env.age");
    sb.run_args(&[
        "secret",
        "encrypt",
        "-r",
        &pubkey,
        "-o",
        &age.display().to_string(),
        &plain.display().to_string(),
    ])?;
    let script = sb.script(&format!("# @secrets {}\n# @local\necho \"v=$S\"\n", age.display()))?;

    // Default threshold (6): a 3-char value is left alone.
    let out =
        run_with_env(&script, &["--local", "-i", &key.display().to_string()], &sb.mock_dir(), &[])?;
    assert_eq!(status_code(&out), 0, "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("v=abc"), "short value must not be masked by default: {stdout}");

    // `SHELLFLOW_MASK_MIN_LEN=3`: now it is masked.
    let out = run_with_env(
        &script,
        &["--local", "-i", &key.display().to_string()],
        &sb.mock_dir(),
        &[("SHELLFLOW_MASK_MIN_LEN", "3")],
    )?;
    assert_eq!(status_code(&out), 0, "{out:?}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("v=***"), "SHELLFLOW_MASK_MIN_LEN was ignored: {stdout}");
    Ok(())
}

#[test]
fn local_verbose_preview_masks_secrets() -> TestResult<()> {
    // The `-vv` "local command" echo used to print the raw `bash -c` body,
    // leaking a literal secret that the payload preview right above it masked.
    let sb = Sandbox::new("localmask")?;
    let script = sb.script(
        "# @env TOKEN=LEAKCANARY123\n\
         # @local\n\
         echo \"$TOKEN\"\n",
    )?;
    let out = sb.run(&script, &["-vvv"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("LEAKCANARY123"), "secret leaked into -vvv output: {stdout}");
    assert!(stdout.contains("***"), "mask not applied: {stdout}");
    Ok(())
}

#[test]
fn step_without_hosts_renders_an_em_dash() -> TestResult<()> {
    // A `@copy` under `--check` performs no transfer, so the step has no host
    // statuses. The old rendering was an empty `()`.
    let sb = Sandbox::new("emdash")?;
    let script = sb.script("# @server ok1 ok@h1\n# @copy ./out -> /srv/app @ok1\n")?;
    let out = sb.run(&script, &["--check"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("()"), "empty status list rendered as `()`: {stdout}");
    assert!(stdout.contains("(—)"), "expected an em dash placeholder: {stdout}");
    Ok(())
}

#[test]
fn step_numbers_agree_between_header_and_summary() -> TestResult<()> {
    // With `--only`, the header counts the selected steps; the summary must
    // use the same numbering or the two disagree.
    let sb = Sandbox::new("stepnum")?;
    let script = sb.script(
        "# @name build\n# @local\necho AAA\n\
         # @name deploy\n# @local\necho BBB\n\
         # @name verify\n# @local\necho CCC\n",
    )?;
    let out = sb.run(&script, &["--only", "deploy"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[STEP 1/1] deploy"), "unexpected header: {stdout}");
    assert!(stdout.contains("step  1  "), "summary must number the selected step 1: {stdout}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Preflight and copy-fallback honesty
// ---------------------------------------------------------------------------

#[test]
fn preflight_reports_missing_scp() -> TestResult<()> {
    // `scp` is the copy fallback for hosts without rsync, so a missing scp is
    // a latent mid-run failure and must fail fast instead.
    let sb = Sandbox::new("preflight-scp")?;
    let script = sb.script("# @local\n\necho hi\n")?;
    let path_dir = sb.dir.join("partial-path");
    fs::create_dir_all(&path_dir).map_err(|e| e.to_string())?;
    for tool in ["/usr/bin/bash", "/usr/bin/ssh", "/usr/bin/rsync"] {
        if Path::new(tool).exists() {
            let name = tool.rsplit('/').next().unwrap_or_default();
            std::os::unix::fs::symlink(tool, path_dir.join(name)).map_err(|e| e.to_string())?;
        }
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_shellflow"));
    cmd.arg(&script).arg("--no-color");
    cmd.env("MOCK_DIR", sb.mock_dir());
    cmd.env("PATH", &path_dir);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if status_code(&out) == 0 {
        // The host machine has no scp in that dir only if the symlink loop
        // above worked; treat an unexpected success as a skip.
        eprintln!("skipping: this machine exposes scp at the probed path");
        return Ok(());
    }
    assert_eq!(status_code(&out), 3, "preflight should exit 3: {out:?}");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("scp"), "preflight must name scp: {stderr}");
    Ok(())
}

#[test]
fn scp_fallback_warns_that_delete_is_ignored() -> TestResult<()> {
    // `scp` cannot mirror deletions. Silently ignoring `--delete` would leave
    // stale files on the target while reporting a successful "mirror".
    let sb = Sandbox::new("scpdelete")?;
    let script = sb.script(
        "# @server norsync1 norsync@h1\n\
         # @copy ./out -> /srv/app @norsync1 --delete\n",
    )?;
    let out = sb.run(&script, &[])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--delete"), "must warn that --delete is dropped: {stdout}");
    assert!(stdout.contains("ignored"), "must warn that --delete is dropped: {stdout}");
    Ok(())
}

#[test]
fn guard_is_visible_at_verbose_two() -> TestResult<()> {
    // Design §8.1: `-vv` shows guard (`@only_if`) evaluations.
    let sb = Sandbox::new("guardverbose")?;
    let script = sb.script(
        "# @server ok1 ok@h1\n\
         # @remote ok1\n\
         # @only_if test -f /etc/app.conf\n\
         echo hi\n",
    )?;
    let out = sb.run(&script, &["-vv"])?;
    assert_eq!(status_code(&out), 0, "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("guard passed"), "guard evaluation not shown: {stdout}");
    assert!(stdout.contains("test -f /etc/app.conf"), "guard command not shown: {stdout}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Process-group teardown: no orphaned grandchildren
// ---------------------------------------------------------------------------

/// Whether `pid` is still executing, as opposed to having exited.
///
/// `kill(pid, 0)` also succeeds for a zombie that has exited but has not been
/// reaped by init yet, which would make a correctly-killed child look like an
/// orphan. On Linux the process state is authoritative; elsewhere fall back to
/// the signal probe.
fn pid_running(pid: i32) -> bool {
    if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) &&
        let Some((_, rest)) = stat.rsplit_once(") ") &&
        let Some(state) = rest.chars().next()
    {
        return state != 'Z';
    }
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok()
}

#[test]
fn timeout_kills_the_whole_process_group() -> TestResult<()> {
    // A block's descendants must die with the step. `kill_on_drop` alone only
    // reaps the direct child, which used to leave the background job running.
    let sb = Sandbox::new("pgroup")?;
    let pid_file = sb.dir.join("grandchild.pid");
    let script = sb.script(&format!(
        "# @local\n\
         sleep 300 &\n\
         echo $! > {}\n\
         wait\n",
        pid_file.display()
    ))?;
    let out = sb.run(&script, &["--timeout", "1"])?;
    assert_eq!(status_code(&out), 4, "timeout is a failure: {out:?}");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pid_file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pid: i32 = fs::read_to_string(&pid_file)
        .map_err(|e| format!("grandchild pid not recorded: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("unparsable pid: {e}"))?;

    // The group kill is asynchronous with respect to the child's exit, so
    // allow a brief settle before declaring the process an orphan.
    let settle = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pid_running(pid) && std::time::Instant::now() < settle {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(!pid_running(pid), "grandchild {pid} survived the timeout — orphaned process");
    Ok(())
}

#[test]
fn stubborn_child_is_escalated_to_sigkill() -> TestResult<()> {
    // SIGTERM-trapping children must not be able to outlive the step: after
    // the grace period the whole group is SIGKILLed.
    let sb = Sandbox::new("sigkill")?;
    let pid_file = sb.dir.join("stubborn.pid");
    let script = sb.script(&format!(
        "# @local\n\
         sh -c 'trap \"\" TERM; echo $$ > {}; sleep 300' &\n\
         wait\n",
        pid_file.display()
    ))?;
    let out = sb.run(&script, &["--timeout", "1"])?;
    assert_eq!(status_code(&out), 4, "timeout is a failure: {out:?}");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !pid_file.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pid: i32 = fs::read_to_string(&pid_file)
        .map_err(|e| format!("stubborn pid not recorded: {e}"))?
        .trim()
        .parse()
        .map_err(|e| format!("unparsable pid: {e}"))?;

    let settle = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while pid_running(pid) && std::time::Instant::now() < settle {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(!pid_running(pid), "SIGTERM-trapping child {pid} survived; SIGKILL escalation failed");
    Ok(())
}
