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

// The ssh-only build still classifies steps: the class is a parameter of the
// step dispatcher (`remote::run_target_step`) and of the target-command
// fan-out, even though only the muxy policy consumes it. Re-exporting it is
// what keeps `--no-default-features` compiling at all.
#[cfg(not(feature = "muxy"))]
pub(crate) use fallback::{StepClass, TransportPolicy};
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

use shellflow_core::{ResolvedHost, SshSpec};
use tokio::process::Command;

use super::process::isolate;

/// Connect timeout for a command step.
pub(crate) const STEP_CONNECT_TIMEOUT_SECS: u64 = 15;

/// Connect timeout for a probe: a probe is a cheap question and must not
/// inherit the operator's `~/.ssh/config` stall budget.
pub(crate) const PROBE_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Connect timeout for a helper / batch invocation.
pub(crate) const BATCH_CONNECT_TIMEOUT_SECS: u64 = 15;

/// The `ssh` options every invocation shares.
///
/// The tool used to assemble `ssh` argv at eight call sites, and the shared
/// policy drifted at each of them: two sites forgot `-T`, three used three
/// different `ConnectTimeout` values, and `--no-ssh-reuse` reached exactly one
/// of them. `BatchMode`, `-T`, the connect bound and `ControlMaster` are
/// decided here, once, and [`apply_options`] is the only code that turns them
/// into argv.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SshPolicy {
    /// Share one authenticated connection across the run (`ControlMaster`).
    reuse: bool,
    /// Connect-phase bound, in seconds.
    connect_timeout: u64,
    /// `ssh -v`, for reproducing a failure by hand at `-vvv`.
    verbose: bool,
}

impl SshPolicy {
    /// A command step: honours `--no-ssh-reuse` and `-vvv`.
    #[must_use]
    pub(crate) const fn step(ssh_reuse: bool, verbose: bool) -> Self {
        Self { reuse: ssh_reuse, connect_timeout: STEP_CONNECT_TIMEOUT_SECS, verbose }
    }

    /// A probe: never reuses a connection, and bounds the connect phase tight.
    #[must_use]
    pub(crate) const fn probe() -> Self {
        Self { reuse: false, connect_timeout: PROBE_CONNECT_TIMEOUT_SECS, verbose: false }
    }

    /// A teardown, a helper ship, or a batch: the invocation owns its channel,
    /// so it neither opens nor joins a multiplexed one.
    #[must_use]
    pub(crate) const fn batch() -> Self {
        Self { reuse: false, connect_timeout: BATCH_CONNECT_TIMEOUT_SECS, verbose: false }
    }
}

/// Append the shared `ssh` options to a command (`std`, so the blocking batch
/// path and the async executor use the same builder).
pub(crate) fn apply_options(policy: SshPolicy, cmd: &mut std::process::Command) {
    // Fail closed on an unknown host key or a missing key: never prompt.
    cmd.args(["-o", "BatchMode=yes"]);
    cmd.arg("-o").arg(format!("ConnectTimeout={}", policy.connect_timeout));
    cmd.arg("-T");
    if policy.reuse {
        cmd.args([
            "-o",
            "ControlMaster=auto",
            "-o",
            "ControlPath=~/.ssh/shellflow-%r@%h-%p",
            "-o",
            "ControlPersist=60",
        ]);
    }
    if policy.verbose {
        cmd.arg("-v");
    }
}

/// The `ssh` command for one resolved destination.
#[must_use]
pub(crate) fn ssh_command(policy: SshPolicy, spec: &SshSpec) -> std::process::Command {
    let mut cmd = std::process::Command::new("ssh");
    apply_options(policy, &mut cmd);
    cmd.args(spec.to_ssh_args());
    cmd
}

/// The `-e` transport string for `rsync` (and the `-S`/`-o` form `scp` takes).
///
/// rsync hands this string to a shell verbatim, so it is the same policy
/// spelled out — not a second, drifting copy of it (`shellflow-dsl` used to
/// own one, which put transport policy inside the pure grammar crate).
#[must_use]
pub(crate) fn rsync_transport(policy: SshPolicy, spec: &SshSpec) -> String {
    let mut out = format!("ssh -o BatchMode=yes -o ConnectTimeout={} -T", policy.connect_timeout);
    if policy.reuse {
        out.push_str(
            " -o ControlMaster=auto -o ControlPath=~/.ssh/shellflow-%r@%h-%p -o ControlPersist=60",
        );
    }
    if let Some(port) = &spec.port {
        out.push_str(&format!(" -p {port}"));
    }
    out
}

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
/// With `ssh_reuse`, later steps in the same run share the first step's
/// authenticated connection; the muxy bridge always forces `ControlMaster=no`
/// instead (a connection that must not be multiplexed).
pub(super) fn ssh_stdin_command(
    host: &ResolvedHost,
    shell_invoke: &str,
    ssh_reuse: bool,
    verbose: bool,
) -> Command {
    let mut cmd = Command::from(ssh_command(SshPolicy::step(ssh_reuse, verbose), &host.spec));
    cmd.arg(shell_invoke);
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    cmd
}

/// Build an `ssh` that runs `remote` as its argv (reload/wait style).
pub(super) fn ssh_argv_command(host: &ResolvedHost, remote: &str, policy: SshPolicy) -> Command {
    let mut cmd = Command::from(ssh_command(policy, &host.spec));
    cmd.arg(remote);
    cmd.kill_on_drop(true);
    isolate(&mut cmd);
    cmd
}

#[cfg(test)]
mod ssh_tests {
    use shellflow_core::SshSpec;

    use super::{SshPolicy, apply_options, rsync_transport, ssh_command};

    fn args(cmd: &std::process::Command) -> Vec<String> {
        cmd.get_args().map(|arg| arg.to_string_lossy().into_owned()).collect()
    }

    fn spec() -> SshSpec {
        SshSpec::parse("deploy@10.0.0.1:2222").expect("a valid spec")
    }

    #[test]
    fn every_invocation_shares_the_fail_closed_options() {
        // The regression this guards: two of the eight spawn sites forgot
        // `-T`, three used three different connect bounds, and only one
        // honoured `--no-ssh-reuse`.
        let rendered = args(&ssh_command(SshPolicy::step(false, false), &spec())).join(" ");
        assert!(rendered.contains("-o BatchMode=yes"), "{rendered}");
        assert!(rendered.contains("-T"), "{rendered}");
        assert!(rendered.contains("ConnectTimeout=15"), "{rendered}");
        assert!(rendered.ends_with("-p 2222 deploy@10.0.0.1"), "{rendered}");
    }

    #[test]
    fn control_master_is_only_added_when_reuse_is_on() {
        let streamed_off = args(&ssh_command(SshPolicy::step(false, false), &spec())).join(" ");
        let streamed_on = args(&ssh_command(SshPolicy::step(true, false), &spec())).join(" ");
        assert!(!streamed_off.contains("ControlMaster"), "{streamed_off}");
        assert!(streamed_on.contains("ControlMaster=auto"), "{streamed_on}");

        // `--no-ssh-reuse` must reach the transfer too: rsync starts its own
        // ssh, and a copy that silently reuses a connection the operator
        // disabled is exactly the drift this builder exists to stop.
        let transfer_off = rsync_transport(SshPolicy::step(false, false), &spec());
        let transfer_on = rsync_transport(SshPolicy::step(true, false), &spec());
        assert!(!transfer_off.contains("ControlMaster"), "{transfer_off}");
        assert!(transfer_on.contains("ControlMaster=auto"), "{transfer_on}");
        assert!(transfer_off.ends_with("-p 2222"), "{transfer_off}");
    }

    #[test]
    fn the_probe_policy_bounds_the_connect_phase_tighter_than_a_step() {
        let rendered = args(&ssh_command(SshPolicy::probe(), &spec())).join(" ");
        assert!(rendered.contains("ConnectTimeout=5"), "{rendered}");
        assert!(!rendered.contains("ControlMaster"), "a probe must answer on its own: {rendered}");
    }

    #[test]
    fn the_batch_path_gets_the_same_options_as_a_step() {
        let mut cmd = std::process::Command::new("ssh");
        apply_options(SshPolicy::batch(), &mut cmd);
        let rendered = args(&cmd).join(" ");
        assert!(rendered.contains("-o BatchMode=yes"), "{rendered}");
        assert!(rendered.contains("-T"), "{rendered}");
    }

    #[test]
    fn verbose_policy_adds_ssh_v() {
        let quiet = args(&ssh_command(SshPolicy::step(false, false), &spec()));
        let verbose = args(&ssh_command(SshPolicy::step(false, true), &spec()));
        assert!(!quiet.contains(&"-v".to_string()));
        assert!(verbose.contains(&"-v".to_string()));
    }
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
