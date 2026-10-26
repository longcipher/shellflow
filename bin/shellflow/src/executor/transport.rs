//! The transport seam: one entry per command step, ssh today, muxy where it
//! works.
//!
//! Three sites used to spawn `ssh` themselves (a remote block, a
//! target-side command, and the reload/wait helpers), each with its own
//! argv builder. They now share the builders below, and the muxy adapter
//! ([`super::muxy`]) implements the same payload shape over the native
//! protocol: [`Payload`] in, lines out through `Ui::host_line`.
//!
//! Policy (which step class may use muxy under `auto`) lives here so both
//! feature configurations share one decision: with the `muxy` feature it is
//! the [`shellflow_muxy`] policy, without it an identical local copy (the
//! ssh-only build still parses `--transport muxy` and fails fast).

#[cfg(not(feature = "muxy"))]
pub(crate) use fallback::TransportPolicy;
#[cfg(feature = "muxy")]
pub(crate) use shellflow_muxy::policy::{StepClass, TransportPolicy, should_use_muxy};

#[cfg(not(feature = "muxy"))]
mod fallback {
    #![expect(dead_code, reason = "the ssh-only build does not use step classes or eligibility")]
    /// Which transport a command step takes to its host.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub(crate) enum TransportPolicy {
        /// Muxy where it works, ssh everywhere else (default).
        #[default]
        Auto,
        /// Every command step through muxy; fail fast when unavailable.
        Muxy,
        /// Never attempt muxy.
        Ssh,
    }

    /// The class of a command step.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[cfg_attr(
        not(feature = "muxy"),
        expect(dead_code, reason = "the ssh-only build never constructs step classes")
    )]
    pub(crate) enum StepClass {
        /// A remote block (`@remote`).
        Remote,
        /// A service lifecycle step (`@service`).
        Service,
        /// A readiness wait (`@wait_active`) or reload.
        Wait,
        /// Reload of a unit.
        Reload,
        /// Builds and dumps that run for minutes.
        LongHelper,
        /// Seconds-long probes (`@assert`, `@install`, …).
        ShortHelper,
        /// Syntax check (`--check`).
        Check,
    }

    impl StepClass {
        /// Short helpers stay on ssh under `auto`: a session each would
        /// flood the operator's terminal list for no gain.
        #[must_use]
        pub(crate) const fn eligible_auto(self) -> bool {
            match self {
                Self::Remote |
                Self::Service |
                Self::Wait |
                Self::Reload |
                Self::LongHelper |
                Self::Check => true,
                Self::ShortHelper => false,
            }
        }
    }

    /// Whether a step of `class` should run through muxy under `policy`.
    #[must_use]
    pub(crate) const fn should_use_muxy(policy: TransportPolicy, class: StepClass) -> bool {
        match policy {
            TransportPolicy::Ssh => false,
            TransportPolicy::Muxy => true,
            TransportPolicy::Auto => class.eligible_auto(),
        }
    }
}

use shellflow_core::ResolvedHost;
use tokio::process::Command;

use super::process::isolate;

/// Map the CLI transport flag to the policy.
#[must_use]
pub(crate) const fn policy_from_cli(arg: crate::cli::TransportArg) -> TransportPolicy {
    match arg {
        crate::cli::TransportArg::Auto => TransportPolicy::Auto,
        crate::cli::TransportArg::Muxy => TransportPolicy::Muxy,
        crate::cli::TransportArg::Ssh => TransportPolicy::Ssh,
    }
}

/// One command payload, transport-independent.
///
/// `env` carries the `@env` entries, the `@secrets` overlay, and the probed
/// login `PATH`; `guard` is the folded `@only_if` (exit 42 means skip).
/// The ssh path renders `env` into an `export` header; the muxy path hands
/// it to the server at session creation so it never touches the disk.
pub(super) struct Payload<'a> {
    /// The block, exactly as written (no `set -eu`, no guard).
    pub script: &'a str,
    /// The folded `@only_if` guard, if any.
    pub guard: Option<&'a str>,
    /// `set -x` tracing at `-vvv`.
    pub trace: bool,
    /// Step environment (literals, secrets overlay, login `PATH`).
    pub env: Vec<(String, String)>,
    /// Per-step timeout in seconds.
    #[cfg_attr(
        not(feature = "muxy"),
        expect(dead_code, reason = "the ssh-only build ignores the muxy deadline")
    )]
    pub timeout: Option<u64>,
}

impl Payload<'_> {
    /// Render the ssh form: `set -eu`, the env header, the folded guard, the
    /// trace flag, and the block.
    ///
    /// A block runs in the login directory (`bash -l -s`), so there is no
    /// `cd`: sessions start at the Home project root for the same reason.
    ///
    /// # Errors
    ///
    /// An `@env` key that is not a valid shell variable name.
    pub(super) fn render_ssh(&self) -> Result<String, shellflow_core::RenderEnvError> {
        let env_header = shellflow_core::render_env(&self.env)?;
        let guard = self.guard.map_or_else(String::new, super::remote::folded_guard);
        Ok(format!("set -eu\n{env_header}{guard}{}{}", self.trace_line(), self.script))
    }

    /// Render the `bash -n -s` form used by the muxy `exec` channel: no
    /// environment and no guard, because a syntax check needs neither and
    /// keeping them out keeps secret material off the wire.
    #[must_use]
    #[cfg_attr(
        not(feature = "muxy"),
        expect(dead_code, reason = "the ssh-only build does not run the exec channel")
    )]
    pub(super) fn render_check(&self) -> String {
        format!("set -eu\n{}{}", self.trace_line(), self.script)
    }

    const fn trace_line(&self) -> &'static str {
        if self.trace { "set -x\n" } else { "" }
    }
}

/// Build an `ssh` that reads the payload from stdin and runs `shell_invoke`.
///
/// Fail-closed on an unknown host key or a missing key: never prompt. With
/// `ssh_reuse`, later steps in the same run share the first step's
/// authenticated connection; the muxy bridge always forces `ControlMaster=no`
/// instead (a connection that must not be multiplexed).
pub(super) fn ssh_stdin_command(
    host: &ResolvedHost,
    shell_invoke: &str,
    ssh_reuse: bool,
    verbose: bool,
) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T");
    if ssh_reuse {
        cmd.args([
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPath=~/.ssh/shellflow-%r@%h-%p",
            "-o",
            "ControlPersist=60",
        ]);
    }
    if verbose {
        cmd.arg("-v");
    }
    cmd.arg(shell_invoke);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    cmd
}

/// Build an `ssh` that runs `remote` as its argv (reload/wait style).
pub(super) fn ssh_argv_command(host: &ResolvedHost, remote: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.args(host.spec.to_ssh_args()).arg("-T").arg(remote);
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    cmd
}

#[cfg(test)]
#[cfg(feature = "muxy")]
mod tests {
    use super::{StepClass, TransportPolicy, should_use_muxy};

    #[test]
    fn auto_routes_long_steps_to_muxy_and_keeps_asserts_on_ssh() {
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Remote));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Service));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Wait));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::Reload));
        assert!(should_use_muxy(TransportPolicy::Auto, StepClass::LongHelper));
        assert!(!should_use_muxy(TransportPolicy::Auto, StepClass::ShortHelper));
    }

    #[test]
    fn forced_muxy_covers_every_class() {
        assert!(should_use_muxy(TransportPolicy::Muxy, StepClass::ShortHelper));
        assert!(!should_use_muxy(TransportPolicy::Ssh, StepClass::Remote));
    }
}
