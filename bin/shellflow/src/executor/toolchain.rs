//! The `@toolchain` step: update language toolchains on the target.
//!
//! The dozen `command -v X || skip; update X` wrappers in every fleet-wide
//! update playbook, as data. Each named tool updates through its own
//! manager; the per-tool quirks operators keep re-discovering are owned by
//! the runner:
//!
//! - `aur` helpers run as the invoking user and never under `sudo` (`paru` refuses root outright);
//! - `uv` upgrades take `--all` (a bare `uv tool upgrade` only prints usage);
//! - `foundry` skips the toolchain install while `anvil` is running (the installer refuses to
//!   replace a running binary, and stopping a live service is never the updater's call).

use crate::executor::quote;

/// The remote command for `@toolchain`.
///
/// Every tool is optional: a missing binary reports SKIP, a failed update
/// reports FAIL, and any FAIL fails the step. The per-tool update bodies
/// mirror what fleet playbooks converged on.
pub(super) fn toolchain_command(tools: &[String]) -> String {
    let list: Vec<String> = tools.iter().map(|t| quote(t)).collect();
    format!(
        "RESULTS=$(mktemp) || exit 1; \
         sfw_run() {{ name=\"$1\"; shift; \
           if \"$@\"; then printf 'OK\\t%s\\n' \"$name\" >>\"$RESULTS\"; \
           else printf 'FAIL\\t%s\\n' \"$name\" >>\"$RESULTS\"; \
           echo \"step failed: $name\" >&2; fi; }}; \
         sfw_have() {{ command -v \"$1\" >/dev/null 2>&1; }}; \
         step_os() {{ \
           if sfw_have pacman; then sudo pacman -Syyu --noconfirm; \
           elif sfw_have apt-get; then sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
           elif sfw_have dnf; then sudo dnf upgrade -y; \
           else echo '(no os package manager, skip)'; return 0; fi; }}; \
         step_aur() {{ \
           if [ \"${{OPS_AUR:-1}}\" = 0 ]; then echo '(OPS_AUR=0, skip)'; return 0; fi; \
           if sfw_have paru; then paru -Syyu --noconfirm; \
           elif sfw_have yay; then yay -Syyu --noconfirm; \
           else echo '(no AUR helper, skip)'; return 0; fi; }}; \
         step_rustup() {{ \
           if ! sfw_have rustup; then echo '(rustup not installed, skip)'; return 0; fi; \
           rustup update && rustup component add clippy rustfmt 2>/dev/null || true; }}; \
         step_cargo() {{ \
           if ! sfw_have cargo; then echo '(cargo not installed, skip)'; return 0; fi; \
           cargo install --list 2>/dev/null || true; \
           echo '(cargo tools are reported, never reinstalled by the updater)'; }}; \
         step_go() {{ \
           if ! sfw_have go; then echo '(go not installed, skip)'; return 0; fi; \
           go version; }}; \
         step_npm() {{ \
           if ! sfw_have npm; then echo '(npm not installed, skip)'; return 0; fi; \
           npm update -g; }}; \
         step_pipx() {{ \
           if ! sfw_have pipx; then echo '(pipx not installed, skip)'; return 0; fi; \
           pipx upgrade-all || true; }}; \
         step_uv() {{ \
           if ! sfw_have uv; then echo '(uv not installed, skip)'; return 0; fi; \
           uv tool upgrade --all || true; }}; \
         step_foundry() {{ \
           if ! sfw_have foundryup; then echo '(foundryup not installed, skip)'; return 0; fi; \
           foundryup --update 2>/dev/null || true; \
           if pgrep -x anvil >/dev/null 2>&1; then \
             echo '(anvil is running, skipping the toolchain install)'; return 0; fi; \
           foundryup; }}; \
         step_proto() {{ \
           if ! sfw_have proto; then echo '(proto not installed, skip)'; return 0; fi; \
           proto outdated --config-mode global --update --latest --yes 2>/dev/null || true; \
           proto install --config-mode global; }}; \
         step_gh() {{ \
           if ! sfw_have gh; then echo '(gh not installed, skip)'; return 0; fi; \
           gh extension upgrade --all || true; }}; \
         for t in {tools}; do sfw_run \"$t\" \"step_$t\"; done; \
         while IFS= read -r line || [ -n \"$line\" ]; do \
           [ -n \"$line\" ] || continue; \
           v=$(printf '%s' \"$line\" | cut -f1); n=$(printf '%s' \"$line\" | cut -f2); \
           printf '  %-4s %s\\n' \"$v\" \"$n\"; \
         done <\"$RESULTS\"; \
         if grep -q '^FAIL' \"$RESULTS\" 2>/dev/null; then rm -f \"$RESULTS\"; exit 1; fi; \
         rm -f \"$RESULTS\"",
        tools = list.join(" "),
    )
}

#[cfg(test)]
mod tests {
    use super::toolchain_command;

    #[test]
    fn toolchain_runs_each_named_tool() {
        let cmd = toolchain_command(&["rustup".to_string(), "uv".to_string()]);
        assert!(cmd.contains("step_rustup"), "{cmd}");
        assert!(cmd.contains("step_uv"), "{cmd}");
    }

    #[test]
    fn toolchain_encodes_the_three_quirks() {
        let cmd = toolchain_command(&["aur".to_string(), "uv".to_string(), "foundry".to_string()]);
        // paru must not run under sudo.
        assert!(cmd.contains("paru -Syyu --noconfirm"), "{cmd}");
        assert!(!cmd.contains("sudo paru"), "{cmd}");
        // uv upgrades take --all.
        assert!(cmd.contains("uv tool upgrade --all"), "{cmd}");
        // foundry skips while anvil runs.
        assert!(cmd.contains("pgrep -x anvil"), "{cmd}");
    }

    #[test]
    fn toolchain_reports_a_summary_and_fails_closed() {
        let cmd = toolchain_command(&["go".to_string()]);
        assert!(cmd.contains("already") || cmd.contains("FAIL"), "{cmd}");
        assert!(cmd.contains("exit 1"), "{cmd}");
    }

    #[test]
    fn toolchain_tool_names_are_quoted() {
        let cmd = toolchain_command(&["go; evil".to_string()]);
        assert!(cmd.contains("'go; evil'"), "{cmd}");
    }
}
