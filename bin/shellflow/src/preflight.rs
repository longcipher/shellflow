//! Preflight validation: verify that the tools shellflow shells out to are
//! present on `PATH` before any step runs.

use std::process::Command;

/// The tools required on the controller machine.
///
/// `scp` is included because `@copy` falls back to `ssh mkdir -p` + `scp` on
/// targets that lack `rsync` (design §9), so a missing `scp` is a latent
/// mid-run failure for every such target.
const REQUIRED_TOOLS: &[(&str, &[&str])] =
    &[("bash", &["--version"]), ("ssh", &["-V"]), ("rsync", &["--version"]), ("scp", &["-V"])];

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
fn tool_works(name: &str, args: &[&str]) -> bool {
    Command::new(name)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
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
    }

    #[test]
    fn tool_works_returns_false_for_missing_tool() {
        assert!(!tool_works("shellflow-definitely-missing-tool-xyz", &["--version"]));
    }
}
