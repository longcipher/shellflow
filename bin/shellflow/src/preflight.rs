//! Preflight validation: verify that the tools shellflow shells out to are
//! present on `PATH` before any step runs.

use std::{env, path::PathBuf, process::Command, time::Duration};

/// How long a `--version`-style probe may run before it is treated as broken.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The tools required on the controller machine.
///
/// `scp` is included because `@copy` falls back to `ssh mkdir -p` + `scp` on
/// targets that lack `rsync` (design §9), so a missing `scp` is a latent
/// mid-run failure for every such target.
const REQUIRED_TOOLS: &[(&str, &[&str])] =
    &[("bash", &["--version"]), ("ssh", &["-V"]), ("rsync", &["--version"]), ("scp", &[])];

/// Verify every required tool is available and executable.
///
/// Returns `Ok(())` when all tools are found, otherwise a message listing the
/// missing tools.
pub(crate) fn preflight_check() -> Result<(), String> {
    check_tools(REQUIRED_TOOLS)
}

/// Verify the tools required by `--local` mode (only `bash`).
pub(crate) fn preflight_check_local() -> Result<(), String> {
    check_tools(&[("bash", &["--version"])])
}

/// Verify that `ssh` is available.
///
/// Used by the subcommands that shell out to `ssh` directly, so a missing
/// tool is reported as the transport/setup failure it is (exit 3) rather
/// than as a generic error.
pub(crate) fn preflight_check_ssh() -> Result<(), String> {
    check_tools(&[("ssh", &["-V"])])
}

fn check_tools(tools: &[(&str, &[&str])]) -> Result<(), String> {
    let missing: Vec<&str> = tools
        .iter()
        .filter(|(name, probe_args)| !tool_works(name, probe_args))
        .map(|(name, _)| *name)
        .collect();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing required tool(s) on PATH: {} — shellflow wraps the system `ssh`/`rsync`/`bash`, so install them first",
            missing.join(", ")
        ))
    }
}

/// Run a probe command and report whether it succeeded.
///
/// An empty probe means "no self-reporting flag exists": the tool is only
/// checked for existence on `PATH`. This is the case for `scp`, which — unlike
/// `ssh -V` / `rsync --version` — has no version flag at all (OpenSSH's
/// `scp` rejects `-V` as an illegal option).
/// Run a probe command and report whether it succeeded within [`PROBE_TIMEOUT`].
///
/// The wait is bounded so a PATH-shadowed wrapper that never exits cannot hang
/// the CLI before the engine — and its timeout machinery — is even running.
fn tool_works(name: &str, args: &[&str]) -> bool {
    if args.is_empty() {
        return which(name).is_some();
    }
    let mut command = Command::new(name);
    command.args(args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    // The probe leads its own process group, exactly like every other child
    // shellflow spawns (design §7.5). Killing only the direct child at the
    // deadline would leave its descendants running after the CLI exits.
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let pid = child.id();

    let deadline = std::time::Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            // Still running at the deadline, or the wait itself failed.
            Ok(None) | Err(_) => {
                // Kill the whole group: the probe may have spawned helpers
                // of its own, and they must not outlive the preflight.
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(pid as i32),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Minimal `which`: the first directory in `PATH` holding an **executable**
/// file with this name.
///
/// The execute bit is checked, not just `is_file()`: design §7.5 exists to
/// prevent a mid-run `Command::new` surprise, and a present-but-non-executable
/// `scp` (0644) would pass an `is_file()` check and then fail every `@copy` to
/// an rsync-less host at run time.
fn which(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let path = env::var_os("PATH")?;
    env::split_paths(&path).map(|dir| dir.join(name)).find(|candidate| {
        candidate
            .metadata()
            .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
    })
}

#[cfg(test)]
mod tests {
    use super::{REQUIRED_TOOLS, preflight_check, tool_works};

    #[test]
    fn required_tools_include_the_scp_fallback() {
        // bash/ssh/rsync drive execution; scp is the copy fallback for hosts
        // without rsync, so all four must be present before any step runs.
        let names: Vec<&str> = REQUIRED_TOOLS.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, vec!["bash", "ssh", "rsync", "scp"]);
    }

    #[test]
    fn preflight_succeeds_on_this_machine() {
        // The test machine runs bash and (normally) ssh/rsync; if any is
        // missing we want a friendly message rather than a panic.
        let result = preflight_check();
        if let Err(msg) = result {
            eprintln!("preflight failed on test machine: {msg}");
        }
        // We only assert on bash, which must exist.
        assert!(tool_works("bash", &["--version"]));
        // `scp` has no version flag (OpenSSH rejects `-V`), so its probe is a
        // plain PATH lookup — this is the regression guard for that path.
        assert!(tool_works("scp", &[]));
        assert!(!tool_works("definitely-not-a-tool-xyz", &[]));
    }

    #[test]
    fn tool_works_returns_false_for_missing_tool() {
        assert!(!tool_works("shellflow-definitely-missing-tool-xyz", &["--version"]));
    }
}
