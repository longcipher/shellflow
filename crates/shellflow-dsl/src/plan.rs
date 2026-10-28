//! The deployment plan data model, target resolution, and state
//! interpolation.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use crate::{
    error::{InterpolateError, ParseError},
    ssh_spec::SshSpec,
};

/// A step target: a server alias, a group name, or a literal ssh spec.
///
/// Classification happens lazily in [`resolve_hosts`] so forward references
/// (a step using a group declared later in the script) work correctly.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Target {
    /// The raw target text from the script (`web`, `@web`, `deploy@host`…).
    pub text: String,
    /// The script line the target was declared on (0 for hand-built targets).
    ///
    /// Carried so a resolution failure (`resolve_hosts`) can point at the
    /// step that named the target instead of an anonymous `line 0`.
    pub line: usize,
}

impl Target {
    /// Create a target from raw script text.
    ///
    /// A leading `@` is stripped so hand-built targets (`Target::new("@web")`)
    /// resolve the same way as parsed ones. Parsed targets carry their
    /// script line; hand-built ones report line 0.
    #[must_use]
    pub fn new(text: impl Into<String>) -> Self {
        Self::at(text, 0)
    }

    /// Create a target from raw script text, remembering the script line.
    #[must_use]
    pub fn at(text: impl Into<String>, line: usize) -> Self {
        let raw: String = text.into();
        let stripped = raw.trim_start_matches('@').trim().to_string();
        Self { text: stripped, line }
    }
}

/// An environment entry injected into subsequent blocks.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EnvEntry {
    /// A literal `KEY=VALUE` from the script.
    Literal {
        /// Variable name.
        key: String,
        /// Literal value.
        value: String,
    },
    /// A bare `KEY` passthrough: the value is read from shellflow's own
    /// environment at execution time.
    Passthrough {
        /// Variable name.
        key: String,
    },
}

/// An encrypted secrets file referenced by `@secrets`.
///
/// The parser records only the path; decryption happens at execution time in
/// the binary, keeping `shellflow-core` pure and I/O-free.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretEntry {
    /// Path to the encrypted age file (`.env.age`).
    pub file: String,
    /// Optional explicit identity path (`--identity`), resolved by the runner.
    pub identity: Option<String>,
}

/// One variable captured by `@export`.
///
/// A captured value is masked in every rendered line **by default**. It is a
/// runtime value the parser never saw, and a playbook routinely exports
/// credentials it just fetched (a vault lookup, a token endpoint), so the
/// variable *name* cannot be the thing that decides whether it is safe to
/// print. `--public` is the explicit, reviewable opt-out for values that are
/// meant to be read in the output (`VERSION`, `COMMIT`); it lives in the
/// playbook next to the declaration instead of in a name heuristic inside the
/// engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportVar {
    /// The shell variable name (`[A-Za-z_][A-Za-z0-9_]*`, already validated).
    pub name: String,
    /// Whether the value may be rendered in the clear (`@export NAME --public`).
    pub public: bool,
}

/// A block of Bash lines executed on the local machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// The Bash lines (comments and statements), verbatim, trailing newline.
    pub script: String,
    /// Optional precondition from `@only_if`.
    pub guard: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
    /// Variables captured into run state after this step (`@export`).
    pub export: Vec<ExportVar>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    ///
    /// Shared, copy-on-write: the plan keeps one list and every step points
    /// at the snapshot that was current when the step was declared, so a
    /// plan with many steps and many `@env` entries stays linear.
    pub env: Arc<Vec<EnvEntry>>,
}

/// A block of Bash lines streamed to the target hosts over SSH.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The Bash lines, verbatim, trailing newline.
    pub script: String,
    /// Optional precondition from `@only_if`.
    pub guard: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    ///
    /// Shared, copy-on-write: see [`LocalStep::env`].
    pub env: Arc<Vec<EnvEntry>>,
}

/// One file or directory to transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyEntry {
    /// Local source path (supports `$VAR`/`${VAR}` interpolation).
    pub src: String,
    /// Remote destination path (supports `$VAR`/`${VAR}` interpolation).
    pub dst: String,
}

/// A local-to-remote file sync step.
///
/// A step may carry **several** entries: consecutive `@copy` directives
/// that share a target and the same options travel in one transfer, so a
/// playbook that ships five templates to the same directory costs one
/// round trip instead of five.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// The files to transfer, in declaration order.
    pub entries: Vec<CopyEntry>,
    /// Target server/group/spec.
    pub target: Target,
    /// Mirror deletions on the remote side (`--delete`).
    pub delete: bool,
    /// Glob patterns to exclude from the transfer (`--exclude`, repeatable).
    ///
    /// Honored by the `rsync` path; the `scp` fallback and `--local` copy
    /// cannot filter files and warn instead.
    pub excludes: Vec<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    ///
    /// `@timeout` is honored for copy steps (it bounds the `rsync`/`scp`
    /// transfer), unlike `guard`.
    pub timeout: Option<u64>,
    /// Environment snapshot (`@env`) in effect when the block was declared.
    ///
    /// Shared, copy-on-write: see [`LocalStep::env`].
    pub env: Arc<Vec<EnvEntry>>,
}

/// A wait-for-active step (`@wait_active`): poll `systemctl is-active`
/// until the unit reports active or the budget expires. Replaces the
/// hand-rolled `for/sleep/ss` poll loops that differ in every playbook
/// (and have shipped with wrong ports).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaitStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// systemd unit name (`foo` or `foo.service`).
    pub unit: String,
    /// Wait budget in seconds (`@timeout` or `--timeout N`, else 300).
    pub timeout: Option<u64>,
    /// Poll interval in seconds (fixed at 5: kind to systemd, not a knob).
    pub interval_secs: u64,
}

/// A graceful reload of a systemd unit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReloadStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// systemd unit name (`foo` or `foo.service`).
    pub unit: String,
    /// Signal to send when the unit declares no `ExecReload=` (`SIGUSR1`).
    pub signal: Option<String>,
    /// Wait for the reload handshake before reporting success.
    pub wait: bool,
    /// How long to wait for the handshake, in seconds.
    pub timeout: Option<u64>,
}

/// The `ActiveState` a `@assert` may require.
///
/// A closed set rather than a free string: `@assert foo active` and
/// `@assert_enabled foo enabled` used to validate their state with different
/// strengths (`[A-Za-z0-9-]` on one path, four legal values on the other), so
/// `# @assert foo banana` parsed and then failed on the target instead of at
/// parse time. Only the steady states `systemctl is-active` reports for a
/// loaded unit are accepted; transient spellings such as `unknown`,
/// `enabled-runtime`, or `linked` are rejected at parse time on purpose, so a
/// typo cannot pass as a state the check would never observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ActiveState {
    /// The unit is running.
    Active,
    /// The unit is reloading (a graceful reload in flight).
    Reloading,
    /// The unit is stopped.
    Inactive,
    /// The unit failed.
    Failed,
    /// The unit is starting.
    Activating,
    /// The unit is stopping.
    Deactivating,
}

impl ActiveState {
    /// The spelling compared against `systemctl is-active` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reloading => "reloading",
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Activating => "activating",
            Self::Deactivating => "deactivating",
        }
    }

    /// Parse a supported state, rejecting anything `is-active` would never
    /// report for a loaded unit (including typos such as `banana`).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "reloading" => Some(Self::Reloading),
            "inactive" => Some(Self::Inactive),
            "failed" => Some(Self::Failed),
            "activating" => Some(Self::Activating),
            "deactivating" => Some(Self::Deactivating),
            _ => None,
        }
    }

    /// Every legal spelling, for an error message.
    #[must_use]
    pub const fn legal() -> &'static str {
        "active, reloading, inactive, failed, activating, or deactivating"
    }
}

/// The enablement a `@assert_enabled` may require.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EnabledState {
    /// Enabled at boot.
    Enabled,
    /// Not enabled at boot.
    Disabled,
    /// Has no `[Install]` section; cannot be enabled.
    Static,
    /// Masked to `/dev/null`.
    Masked,
}

impl EnabledState {
    /// The spelling compared against `systemctl is-enabled` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Static => "static",
            Self::Masked => "masked",
        }
    }

    /// Parse a supported enablement, rejecting transient spellings such as
    /// `enabled-runtime` or `linked` (and typos) at parse time.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "enabled" => Some(Self::Enabled),
            "disabled" => Some(Self::Disabled),
            "static" => Some(Self::Static),
            "masked" => Some(Self::Masked),
            _ => None,
        }
    }

    /// Every legal spelling, for an error message.
    #[must_use]
    pub const fn legal() -> &'static str {
        "enabled, disabled, static, or masked"
    }
}

/// One condition an `@assert` step checks on the target.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Assertion {
    /// The systemd unit's `ActiveState` must equal the expected state.
    UnitState {
        /// The systemd unit name (`foo.service`).
        unit: String,
        /// The expected `ActiveState` (`active`).
        state: ActiveState,
    },
    /// The systemd unit's enablement must equal the expected state.
    ///
    /// Replaces the hand-written `systemctl is-enabled` audit loops that
    /// every fleet ends up with: the expected boot state is declared next
    /// to the unit, and drift (a stopped service re-enabled, an enabled
    /// service that should stay dormant) is a deployment-time failure.
    Enabled {
        /// The systemd unit name (`foo.service`).
        unit: String,
        /// The expected `is-enabled` output (`enabled`).
        state: EnabledState,
    },
    /// The URL must answer with an accepted HTTP status.
    Health {
        /// The URL to probe.
        url: String,
        /// The accepted status codes: an exact code (`200`) or a class
        /// (`2xx`). Any 2xx or 3xx by default.
        expect: Vec<String>,
        /// The HTTP method (`GET` by default).
        method: Option<String>,
        /// The request body, for a method that takes one.
        body: Option<String>,
        /// Extra request headers (`Name: value`).
        headers: Vec<String>,
    },
    /// The ports must be listening on the target.
    Port {
        /// The ports that must be listening.
        ports: Vec<u16>,
        /// Whether the ports are UDP rather than TCP.
        udp: bool,
    },
    /// The ports must be free on the target.
    ///
    /// The failure message attributes the occupant (the listening process,
    /// a `nft`/`iptables` DNAT rule, or a container publish mapping) so the
    /// operator does not need the manual `ss`/`nft`/`podman` archaeology
    /// that a bind conflict otherwise requires.
    PortFree {
        /// The ports that must have no listener.
        ports: Vec<u16>,
    },
    /// The file must exist and hold no unexpanded `${…}` placeholder.
    Rendered {
        /// The remote path of the rendered file.
        path: String,
    },
    /// No credential value may appear in the unit's journal or its argv.
    ///
    /// The check is **value based**: the target-side helper decrypts the
    /// service's own credential store and looks for the real values, so a
    /// playbook needs no per-service regular expression and the plaintext
    /// never reaches the script, the command line, or the operator's log.
    NoLeak {
        /// The systemd unit whose journal and argv are scanned.
        unit: String,
        /// How many journal lines to scan.
        lines: Option<u64>,
    },
    /// The file must exist and match a digest.
    ///
    /// This is a real drift gate: the hand-written `md5sum` in a playbook
    /// printed a digest that nothing compared.
    Digest {
        /// The remote path of the file.
        path: String,
        /// The expected sha256 hex digest.
        sha256: Option<String>,
        /// A controller-side file to compare the remote file against.
        local: Option<String>,
    },
    /// The credential store of a service must exist and agree with the
    /// credential keys the unit declares.
    Credstore {
        /// The service name (the credential-store directory name).
        service: String,
    },
}

/// A systemd unit lifecycle step (`@service`).
///
/// The step owns the whole sequence a deploy playbook used to spell out in
/// shell — verify the unit, reload the manager, enable it, restart it, wait
/// for it — and it owns the rules that the shell spelling got wrong:
///
/// - a unit that was **not active before** is not started by `--restart` (restarting an inactive
///   unit starts it, which is the opposite of what an operator who keeps a unit stopped intends);
/// - `--verify` fails closed: an invalid unit aborts the deploy before the manager is reloaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// systemd unit name (`foo` or `foo.service`).
    pub unit: String,
    /// Enable the unit at boot (`systemctl enable`).
    pub enable: bool,
    /// Restart the unit — but only if it was active before.
    pub restart: bool,
    /// Reload the unit gracefully instead of restarting it.
    pub reload: bool,
    /// Wait for the unit to report ready after the action.
    pub wait: bool,
    /// Verify the installed unit before touching the manager.
    pub verify: bool,
    /// Start the unit even when it was not active before.
    pub force_start: bool,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// An atomic file install on the target (`@install`).
///
/// The install writes to a temporary file **in the destination directory**
/// and renames it into place, so a reader (systemd, `systemctl cat`, a
/// concurrent `daemon-reload`) never observes a half-written unit file,
/// config, or binary — which the `install -m …` spelling did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The source path **on the target**.
    pub src: String,
    /// The destination path **on the target**.
    pub dst: String,
    /// The file mode to set (octal, e.g. `0644`).
    pub mode: Option<u32>,
    /// The `user:group` to own the file.
    pub owner: Option<String>,
    /// The mode of the destination directory, created when missing.
    pub dir_mode: Option<u32>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A backup snapshot step (`@backup`).
///
/// The step keeps the rollback copy **and** the retention rule in one place,
/// and it asserts on the files it wrote itself rather than re-globbing the
/// snapshot directory through a pipeline that cannot fail.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The paths to snapshot, all **on the target**.
    pub paths: Vec<String>,
    /// The service the snapshot belongs to (the snapshot directory name).
    pub service: Option<String>,
    /// How many snapshots to keep.
    pub keep: Option<u32>,
    /// Encrypt the snapshot with the host key, so no plaintext lands on disk.
    pub seal: bool,
    /// The snapshot directory (default `/root/<service>-backup-<stamp>`).
    pub dir: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A credential-store step (`@credstore`).
///
/// Seals the service's credential store and checks it against the keys the
/// unit actually declares, so a mismatch is a deployment-time failure with a
/// readable message instead of a unit that fails to start with a cryptic
/// systemd error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredstoreStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The service name (the credential-store directory name).
    pub service: String,
    /// Credential keys that must be present.
    pub require: Vec<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A unit inventory report (`@unit_inventory`).
///
/// Lists the units installed on the target and compares them with the units
/// the repository manages. It is a **report**, not a gate: a pre-existing
/// finding must never block an unrelated deploy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitInventoryStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A target-helper build and install step (`@helper`).
///
/// The helper is the target-side `shellflow` binary every other primitive
/// delegates to. Building it on the controller and shipping it is a repeated,
/// expensive, and easily-mistyped operation; this step does it once, caches
/// the artifact by source revision and target triple, and installs it
/// atomically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HelperStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The source tree to build (default: `$SHELLFLOW_SRC`).
    pub source: Option<String>,
    /// The target triple to build for (default: `x86_64-unknown-linux-musl`).
    pub triple: Option<String>,
    /// Where to install the helper on the target.
    pub install_path: String,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A GitHub-release tracking step (`@release`).
///
/// Replaces the hand-written version-compare blocks (`--version` output vs
/// the `releases/latest` redirect) that every binary-from-release service
/// repeats: the step resolves the newest release tag, compares it against
/// the installed binary, and downloads the matching asset only when they
/// differ. No download means no restart downstream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The `owner/repo` whose releases are tracked.
    pub repo: String,
    /// Command that prints the installed version
    /// (e.g. `/opt/dufs/bin/dufs --version`).
    pub installed_cmd: String,
    /// Asset name template for the release download. Supports `{tag}`
    /// (the `v`-prefixed tag) and `{version}` (the tag without `v`).
    pub asset: String,
    /// Directory the asset is downloaded and extracted into.
    pub to_dir: String,
    /// Download base URL (default `https://github.com/<repo>/releases/download`).
    /// A vendor CDN (e.g. `https://downloads.openobserve.ai/releases/openobserve`)
    /// goes here; `{tag}`/`{version}` are **not** expanded in it.
    pub base_url: Option<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A source-build step (`@build`).
///
/// The native-build half of the binary catalog: check out the pinned ref,
/// build on the target (native glibc, no cross), probe the fresh binary,
/// back up the running one, and install atomically. The manifest fields are
/// data — the chain (fetch → build → probe → backup → install → verify)
/// is owned by the runner, so a new service adds one declarative block
/// instead of a new build script.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The git repository to build from.
    pub repo: String,
    /// An existing checkout to build in, instead of the managed
    /// `~/src/shellflow-builds/<name>` directory. Required when the build
    /// needs sibling checkouts (cross-repo `path = "../..."` dependencies).
    /// Must already be a git checkout; the runner fetches and detaches the
    /// ref there but never touches uncommitted files (a dirty tree fails
    /// the checkout instead of being reset).
    pub workdir: Option<String>,
    /// The pinned ref: tag, branch, or commit sha.
    pub git_ref: String,
    /// The build command, run at the repository root
    /// (e.g. `cargo build --release -p myapp`).
    pub build_cmd: String,
    /// A preparation command, run at the repository root after checkout and
    /// before the build (e.g. `git submodule update --init --recursive`).
    pub prep_cmd: Option<String>,
    /// Build artifacts, relative to the cargo target directory,
    /// each optionally renamed with `path=name`.
    pub artifacts: Vec<String>,
    /// Directories the artifacts are installed into.
    pub install_dirs: Vec<String>,
    /// Units restarted after the install (only when previously active).
    pub units: Vec<String>,
    /// Flag that prints the binary's version for the preflight probe
    /// (`--version`); empty skips the probe.
    pub version_flag: String,
    /// Minimum free disk (GB) required before building.
    pub min_free_gb: u64,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A language-toolchain update step (`@toolchain`).
///
/// The dozen `command -v X || skip; update X` wrappers in every fleet-wide
/// update playbook, as data: each named tool updates through its own
/// manager, and the per-tool quirks (the ones operators keep
/// re-discovering) are owned by the runner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolchainStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// Tool names to update (`rustup`, `cargo`, `go`, `npm`, `pipx`,
    /// `uv`, `foundry`, `proto`, `gh`).
    pub tools: Vec<String>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A container-image update step (`@image`).
///
/// Pulls each image, compares the digest before and after, and reports
/// which images actually moved — the pull/compare/prune loop every
/// container fleet hand-writes, owned by the runner instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// Images to pull (`name:tag`).
    pub images: Vec<String>,
    /// Prune dangling images after the pull.
    pub prune: bool,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// A step that asserts conditions on the target hosts.
///
/// Assertions replace the hand-written `systemctl is-active && curl -f`
/// tails that every playbook ends with — the part that differs in every
/// playbook and that silently stops being checked when somebody edits it.
///
/// Consecutive assertions that share a target are **one** step, so a
/// playbook that checks three things still costs one round trip.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssertStep {
    /// Optional label from `@name`.
    pub name: Option<String>,
    /// Target server/group/spec.
    pub target: Target,
    /// The conditions to check, in declaration order.
    pub checks: Vec<Assertion>,
    /// Optional per-step timeout in seconds from `@timeout`.
    pub timeout: Option<u64>,
}

/// One executable unit of the plan.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Step {
    /// Execute Bash locally.
    Local(LocalStep),
    /// Stream Bash to remote hosts.
    Remote(RemoteStep),
    /// Sync a file/dir to remote hosts with rsync.
    Copy(CopyStep),
    /// Wait for a systemd unit to report active.
    Wait(WaitStep),
    /// Reload a systemd unit gracefully.
    Reload(ReloadStep),
    /// Assert conditions on the target hosts.
    Assert(AssertStep),
    /// Drive a systemd unit's lifecycle.
    Service(ServiceStep),
    /// Install a file on the target atomically.
    Install(InstallStep),
    /// Snapshot files on the target for rollback.
    Backup(BackupStep),
    /// Seal and verify a service's credential store.
    Credstore(CredstoreStep),
    /// Report the units installed on the target.
    UnitInventory(UnitInventoryStep),
    /// Build and install the target-side helper.
    Helper(HelperStep),
    /// Track a GitHub release and download the asset on drift.
    Release(ReleaseStep),
    /// Build a pinned ref from source on the target.
    Build(BuildStep),
    /// Update language toolchains on the target.
    Toolchain(ToolchainStep),
    /// Pull container images and report digest drift.
    Image(ImageStep),
}

impl Step {
    /// The step's display name, if `@name` was set.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Local(s) => s.name.as_deref(),
            Self::Remote(s) => s.name.as_deref(),
            Self::Copy(s) => s.name.as_deref(),
            Self::Wait(s) => s.name.as_deref(),
            Self::Reload(s) => s.name.as_deref(),
            Self::Assert(s) => s.name.as_deref(),
            Self::Service(s) => s.name.as_deref(),
            Self::Install(s) => s.name.as_deref(),
            Self::Backup(s) => s.name.as_deref(),
            Self::Credstore(s) => s.name.as_deref(),
            Self::UnitInventory(s) => s.name.as_deref(),
            Self::Helper(s) => s.name.as_deref(),
            Self::Release(s) => s.name.as_deref(),
            Self::Build(s) => s.name.as_deref(),
            Self::Toolchain(s) => s.name.as_deref(),
            Self::Image(s) => s.name.as_deref(),
        }
    }

    /// The step kind as a short stable string (`local` | `remote` | `copy` |
    /// `wait_active`).
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Local(_) => "local",
            Self::Remote(_) => "remote",
            Self::Copy(_) => "copy",
            Self::Wait(_) => "wait_active",
            Self::Reload(_) => "reload",
            Self::Assert(_) => "assert",
            Self::Service(_) => "service",
            Self::Install(_) => "install",
            Self::Backup(_) => "backup",
            Self::Credstore(_) => "credstore",
            Self::UnitInventory(_) => "unit_inventory",
            Self::Helper(_) => "helper",
            Self::Release(_) => "release",
            Self::Build(_) => "build",
            Self::Toolchain(_) => "toolchain",
            Self::Image(_) => "image",
        }
    }

    /// The target of the steps that run against hosts.
    ///
    /// Consumers that need the target itself (to resolve hosts, to key a
    /// per-host secret file) use this instead of matching all sixteen
    /// variants, so a new step variant does not fan out into six matches.
    #[must_use]
    pub const fn target(&self) -> Option<&Target> {
        match self {
            Self::Local(_) => None,
            Self::Remote(s) => Some(&s.target),
            Self::Copy(s) => Some(&s.target),
            Self::Wait(s) => Some(&s.target),
            Self::Reload(s) => Some(&s.target),
            Self::Assert(s) => Some(&s.target),
            Self::Service(s) => Some(&s.target),
            Self::Install(s) => Some(&s.target),
            Self::Backup(s) => Some(&s.target),
            Self::Credstore(s) => Some(&s.target),
            Self::UnitInventory(s) => Some(&s.target),
            Self::Helper(s) => Some(&s.target),
            Self::Release(s) => Some(&s.target),
            Self::Build(s) => Some(&s.target),
            Self::Toolchain(s) => Some(&s.target),
            Self::Image(s) => Some(&s.target),
        }
    }

    /// The target text, for remote and copy steps.
    #[must_use]
    pub fn target_text(&self) -> Option<&str> {
        self.target().map(|target| target.text.as_str())
    }

    /// The guard command, if `@only_if` was set.
    #[must_use]
    pub fn guard(&self) -> Option<&str> {
        match self {
            Self::Local(s) => s.guard.as_deref(),
            Self::Remote(s) => s.guard.as_deref(),
            Self::Copy(_) |
            Self::Wait(_) |
            Self::Reload(_) |
            Self::Assert(_) |
            Self::Service(_) |
            Self::Install(_) |
            Self::Backup(_) |
            Self::Credstore(_) |
            Self::UnitInventory(_) |
            Self::Helper(_) |
            Self::Release(_) |
            Self::Build(_) |
            Self::Toolchain(_) |
            Self::Image(_) => None,
        }
    }

    /// The per-step timeout in seconds, if `@timeout` was set.
    #[must_use]
    pub const fn timeout(&self) -> Option<u64> {
        match self {
            Self::Local(s) => s.timeout,
            Self::Remote(s) => s.timeout,
            Self::Copy(s) => s.timeout,
            Self::Wait(s) => s.timeout,
            Self::Reload(s) => s.timeout,
            Self::Assert(s) => s.timeout,
            Self::Service(s) => s.timeout,
            Self::Install(s) => s.timeout,
            Self::Backup(s) => s.timeout,
            Self::Credstore(s) => s.timeout,
            Self::UnitInventory(s) => s.timeout,
            Self::Helper(s) => s.timeout,
            Self::Release(s) => s.timeout,
            Self::Build(s) => s.timeout,
            Self::Toolchain(s) => s.timeout,
            Self::Image(s) => s.timeout,
        }
    }
}

/// A managed temporary directory for one run (`@workdir`).
///
/// The playbook's `STAMP="$(date +%s)"; WORKDIR="/tmp/$STAMP"; mkdir -p …`
/// left a directory behind on every run — including the cross-compiled
/// helper binary — and nothing ever removed it. A managed workdir is created
/// once per run, published to the run state as `WORKDIR`, and removed on
/// every exit path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Workdir {
    /// The directory name prefix (default `shellflow`).
    pub prefix: String,
}

/// Fully parsed deployment plan.
///
/// The fields are private and read through accessors: a plan is a value with
/// invariants (every `@export` name was validated, every target resolved to a
/// declared alias or a valid spec), and a public mutable field would let a
/// consumer break them and skip the validation the parser did.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct ExecutionPlan {
    /// Server aliases in declaration order (BTreeMap keeps summaries stable).
    pub(crate) servers: BTreeMap<String, SshSpec>,
    /// Group aliases to server member lists.
    pub(crate) groups: BTreeMap<String, Vec<String>>,
    /// All `@env` entries in declaration order.
    ///
    /// Copy-on-write behind an `Arc`: every step snapshots the list as it was
    /// declared by holding an `Arc` clone, so snapshotting the environment into
    /// every step costs one pointer copy rather than a deep copy of every
    /// key/value pair. A step's `env` field therefore shares one allocation
    /// with every other step declared between two `@env` directives.
    pub(crate) env: Arc<Vec<EnvEntry>>,
    /// All `@secrets` file references in declaration order.
    pub(crate) secrets: Vec<SecretEntry>,
    /// The managed work directory for this run (`@workdir`).
    pub(crate) workdir: Option<Workdir>,
    /// The steps, in declaration order.
    pub(crate) steps: Vec<Step>,
}

impl ExecutionPlan {
    /// The declared servers, keyed by alias.
    #[must_use]
    pub const fn servers(&self) -> &BTreeMap<String, SshSpec> {
        &self.servers
    }

    /// The declared groups: alias to member aliases.
    #[must_use]
    pub const fn groups(&self) -> &BTreeMap<String, Vec<String>> {
        &self.groups
    }

    /// The `@env` entries in declaration order.
    #[must_use]
    pub const fn env(&self) -> &Arc<Vec<EnvEntry>> {
        &self.env
    }

    /// The `@secrets` references in declaration order.
    #[must_use]
    pub fn secrets(&self) -> &[SecretEntry] {
        &self.secrets
    }

    /// The managed work directory, when the playbook declared one.
    #[must_use]
    pub const fn workdir(&self) -> Option<&Workdir> {
        self.workdir.as_ref()
    }

    /// The steps, in declaration order.
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }
}

/// Cross-step state captured by `@export`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RunState {
    /// Variable name to captured value.
    pub vars: BTreeMap<String, String>,
}

/// A concrete host resolved from a target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedHost {
    /// Display alias used for log prefixes (`web1`).
    pub alias: String,
    /// The concrete ssh destination.
    pub spec: SshSpec,
}

/// Resolve a step target into concrete hosts.
///
/// Resolution order: group → server alias → raw ssh spec. When `restrict` is
/// non-empty (the CLI `--target` flag), only aliases belonging to the listed
/// servers/groups are kept.
///
/// # Errors
///
/// Returns a [`ParseError`] when the target is neither a known alias nor a
/// valid raw ssh spec.
pub fn resolve_hosts(
    plan: &ExecutionPlan,
    target: &Target,
    restrict: &[String],
) -> Result<Vec<ResolvedHost>, ParseError> {
    let normalized = target.text.trim_start_matches('@').trim().to_string();
    if normalized.is_empty() {
        return Err(ParseError::EmptyTarget { target: target.text.clone() });
    }
    let mut hosts: Vec<ResolvedHost> = Vec::new();
    if let Some(members) = plan.groups.get(&normalized) {
        for member in members {
            // A member with no `@server` is a plan error, not a host to skip
            // silently: `parse_script` validates this today, but
            // `resolve_hosts` is public API and must not quietly drop a host
            // when handed a hand-built plan.
            let spec = plan.servers.get(member).ok_or_else(|| ParseError::UnknownGroupMember {
                line: target.line,
                group: normalized.clone(),
                server: member.clone(),
            })?;
            hosts.push(ResolvedHost { alias: member.clone(), spec: spec.clone() });
        }
    } else if let Some(spec) = plan.servers.get(&normalized) {
        hosts.push(ResolvedHost { alias: normalized, spec: spec.clone() });
    } else {
        let spec = SshSpec::parse(&normalized).map_err(|mut err| {
            if let ParseError::InvalidSshSpec { line, .. } = &mut err {
                *line = target.line;
            }
            err
        })?;
        hosts.push(ResolvedHost { alias: normalized, spec });
    }

    if restrict.is_empty() {
        return Ok(hosts);
    }
    let allowed = allowed_aliases(plan, restrict);
    let filtered: Vec<ResolvedHost> =
        hosts.into_iter().filter(|host| allowed.contains(&host.alias)).collect();
    if filtered.is_empty() {
        return Err(ParseError::EmptyTarget { target: target.text.clone() });
    }
    Ok(filtered)
}

/// Expand a `--target` restriction list into the set of allowed server
/// aliases (group names expand to their members).
fn allowed_aliases(plan: &ExecutionPlan, restrict: &[String]) -> HashSet<String> {
    let mut allowed = HashSet::new();
    for item in restrict {
        let normalized = item.trim_start_matches('@').trim();
        if let Some(members) = plan.groups.get(normalized) {
            allowed.extend(members.iter().cloned());
        } else {
            allowed.insert(normalized.to_string());
        }
    }
    allowed
}

/// The shell-identifier rule, shared with the runtime and the secrets crate.
// Owned by `shellflow-text`; imported here for `interpolate`. This used to be
// a `pub use`, which made `shellflow_dsl::plan::is_valid_var_name` a third
// authoritative path to the rule.
use shellflow_text::is_valid_var_name;

/// Interpolate `$VAR` and `${VAR}` references in a copy path against the run
/// state.
///
/// A stray `$` (not followed by a valid name) and an unterminated `${` are
/// copied literally. An unresolved variable name is an error — never a silent
/// no-op.
///
/// # Errors
///
/// Returns [`InterpolateError::Unresolved`] when a referenced variable is
/// missing from the state.
pub fn interpolate(template: &str, state: &RunState) -> Result<String, InterpolateError> {
    let mut out = String::with_capacity(template.len());
    // The scanner advances by *consuming* the iterator, never by adding to
    // an index: an index that stops advancing would loop forever.
    let mut chars = template.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '$' {
            out.push(ch);
            continue;
        }

        if chars.peek().is_some_and(|(_, next)| *next == '{') {
            // `${NAME}`: the closing brace ends the reference.
            chars.next();
            let mut name = String::new();
            let mut closed = false;
            for (_, c) in chars.by_ref() {
                if c == '}' {
                    closed = true;
                    break;
                }
                name.push(c);
            }
            if closed && is_valid_var_name(&name) {
                let value = state.vars.get(&name).ok_or_else(|| InterpolateError::Unresolved {
                    var: name.clone(),
                    template: template.to_string(),
                })?;
                out.push_str(value);
            } else {
                // Not a reference: the `$` is literal and the braces are
                // copied as they are.
                out.push('$');
                out.push('{');
                out.push_str(&name);
                if closed {
                    out.push('}');
                }
            }
            continue;
        }

        // `$NAME`: the name runs to the first character that cannot be part
        // of an identifier.
        let mut name = String::new();
        while let Some((_, c)) = chars.peek().copied() {
            if !(c.is_ascii_alphanumeric() || c == '_') {
                break;
            }
            name.push(c);
            chars.next();
        }
        if is_valid_var_name(&name) {
            let value = state.vars.get(&name).ok_or_else(|| InterpolateError::Unresolved {
                var: name.clone(),
                template: template.to_string(),
            })?;
            out.push_str(value);
        } else {
            out.push('$');
            out.push_str(&name);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{error::ParseError, parser::parse_script};

    #[test]
    fn resolve_group_expands_to_members() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &[]).map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].alias, "web1");
        assert_eq!(hosts[1].alias, "web2");
        Ok(())
    }

    #[test]
    fn resolve_single_server() -> Result<(), String> {
        let plan = parse_script("# @server web1 deploy@10.0.0.1\n").map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web1"), &[]).map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "web1");
        Ok(())
    }

    #[test]
    fn resolve_raw_spec_fallback() -> Result<(), String> {
        let plan = ExecutionPlan::default();
        let hosts = resolve_hosts(&plan, &Target::new("deploy@10.0.0.9:2222"), &[])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "deploy@10.0.0.9:2222");
        assert_eq!(hosts[0].spec.port, Some(2222));
        Ok(())
    }

    #[test]
    fn resolve_respects_restrict() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &["web2".to_string()])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].alias, "web2");
        Ok(())
    }

    #[test]
    fn resolve_group_name_in_restrict() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        let hosts = resolve_hosts(&plan, &Target::new("web"), &["web".to_string()])
            .map_err(|e| e.to_string())?;
        assert_eq!(hosts.len(), 2);
        Ok(())
    }

    #[test]
    fn interpolate_dollar_var() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("VERSION".to_string(), "abc123".to_string());
        let out = interpolate("target/myapp-$VERSION", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "target/myapp-abc123");
        Ok(())
    }

    #[test]
    fn interpolate_braced_var() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("VERSION".to_string(), "abc123".to_string());
        let out = interpolate("${VERSION}/app", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "abc123/app");
        Ok(())
    }

    #[test]
    fn interpolate_unresolved_is_error() {
        let state = RunState::default();
        assert!(matches!(
            interpolate("x-$MISSING", &state),
            Err(InterpolateError::Unresolved { .. })
        ));
    }

    #[test]
    fn interpolate_stray_dollar_is_literal() -> Result<(), String> {
        let state = RunState::default();
        let out =
            interpolate("cost is $5 and ${unterminated", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "cost is $5 and ${unterminated");
        // An empty braced reference emits a literal `$` and keeps the
        // remaining `{}` as ordinary characters.
        let empty = interpolate("${}x", &state).map_err(|e| e.to_string())?;
        assert_eq!(empty, "${}x");
        Ok(())
    }

    #[test]
    fn interpolate_invalid_braced_name_is_literal() -> Result<(), String> {
        // A braced name that is not a valid shell identifier is kept verbatim
        // (mirrors the unbraced scanner).
        let state = RunState::default();
        let out = interpolate("${1BAD}-$9", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "${1BAD}-$9");
        Ok(())
    }

    #[test]
    fn resolve_empty_after_restrict_is_error() -> Result<(), String> {
        let plan = parse_script(
            "# @server web1 deploy@10.0.0.1\n\
             # @server web2 deploy@10.0.0.2\n\
             # @group web web1,web2\n",
        )
        .map_err(|e| e.to_string())?;
        // Restricting to an unrelated server filters out every host.
        let err = match resolve_hosts(&plan, &Target::new("web"), &["db1".to_string()]) {
            Err(err) => err,
            Ok(_) => return Err("restriction should empty the target".to_string()),
        };
        match err {
            ParseError::EmptyTarget { target } => assert_eq!(target, "web"),
            other => return Err(format!("expected EmptyTarget, got {other:?}")),
        }
        Ok(())
    }

    #[test]
    fn step_metadata_accessors() -> Result<(), String> {
        let plan = parse_script(
            "# @name build\n\
             # @local\n\
             echo hi\n\
             # @name ship\n\
             # @copy a -> b @web\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].name(), Some("build"));
        assert_eq!(plan.steps[0].kind(), "local");
        assert_eq!(plan.steps[1].name(), Some("ship"));
        assert_eq!(plan.steps[1].kind(), "copy");
        assert_eq!(plan.steps[1].target_text(), Some("web"));
        Ok(())
    }

    #[test]
    fn step_guard_and_timeout_accessors() -> Result<(), String> {
        let plan = parse_script(
            "# @name restart\n\
             # @only_if test -f /etc/app.conf\n\
             # @timeout 30\n\
             # @remote web\n\
             sudo systemctl restart app\n",
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].guard(), Some("test -f /etc/app.conf"));
        assert_eq!(plan.steps[0].timeout(), Some(30));
        // A step without metadata yields None for both.
        let bare = parse_script("# @local\n\necho hi\n").map_err(|e| e.to_string())?;
        assert_eq!(bare.steps[0].guard(), None);
        assert_eq!(bare.steps[0].timeout(), None);
        Ok(())
    }

    #[test]
    fn a_value_containing_a_reference_is_not_re_expanded() -> Result<(), String> {
        // Single-pass by design: a captured value may legitimately contain a
        // `$` (a password like `p$w`), and re-scanning it would corrupt the
        // path it was substituted into.
        let mut state = RunState::default();
        state.vars.insert("X".to_string(), "$Y".to_string());
        state.vars.insert("Y".to_string(), "1".to_string());
        let out = interpolate("$X", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "$Y");
        Ok(())
    }

    #[test]
    fn a_stray_dollar_next_to_a_value_is_not_a_reference() -> Result<(), String> {
        // `$$` is a literal `$` followed by the expansion of `X`. Only a second
        // pass would read `$abc` as a reference to `abc`, which is why
        // interpolation is single-pass and non-idempotent by design.
        let mut state = RunState::default();
        state.vars.insert("X".to_string(), "abc".to_string());
        state.vars.insert("abc".to_string(), "zzz".to_string());
        let out = interpolate("$${X}", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "$abc");
        Ok(())
    }

    #[test]
    fn interpolate_underscore_and_braced_names() -> Result<(), String> {
        let mut state = RunState::default();
        state.vars.insert("_REV".to_string(), "abc123".to_string());
        state.vars.insert("DEPLOY_TAG".to_string(), "v1.2".to_string());
        let out = interpolate("app-${_REV}-${DEPLOY_TAG}", &state).map_err(|e| e.to_string())?;
        assert_eq!(out, "app-abc123-v1.2");
        // Unbraced names exercise the `$NAME` scanner, including leading
        // underscores.
        let unbraced = interpolate("$_REV-$DEPLOY_TAG", &state).map_err(|e| e.to_string())?;
        assert_eq!(unbraced, "abc123-v1.2");
        Ok(())
    }

    proptest::proptest! {
        /// A template without `$` is returned byte-for-byte, whatever the run
        /// state holds: interpolation may only ever touch `$` references.
        #[test]
        fn interpolate_is_identity_without_dollar(
            text in "[^$]{0,40}",
            (key, value) in ("[A-Za-z_][A-Za-z0-9_]{0,8}", "[^$]{0,20}"),
        ) {
            let mut state = RunState::default();
            state.vars.insert(key, value);
            let out = interpolate(&text, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &text);
        }

        /// `$NAME` and `${NAME}` agree, and only the valid `[A-Za-z_]\w*` name
        /// is consumed — the following separator must survive.
        #[test]
        fn braced_and_unbraced_forms_agree(
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9]{1,12}",
            suffix in prop_oneof![
                Just(String::new()),
                Just("/".to_string()),
                Just("-x".to_string()),
            ],
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value.clone());
            let unbraced =
                interpolate(&format!("${name}{suffix}"), &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let braced =
                interpolate(&format!("${{{name}}}{suffix}"), &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&unbraced, &format!("{value}{suffix}"));
            prop_assert_eq!(braced, unbraced);
        }

        /// A fully-resolved template leaves no `$` behind.
        #[test]
        fn every_reference_is_expanded(
            prefix in "[a-z/]{0,10}",
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9]{1,12}",
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value);
            let out = interpolate(&format!("{prefix}${{{name}}}"), &state)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(!out.contains('$'), "unexpanded reference left in {out:?}");
        }

        /// Every stray `$` shape is copied literally and never errors — an
        /// unresolvable-looking `$` must not abort a deploy.
        #[test]
        fn stray_dollar_is_literal_never_an_error(
            stray in prop_oneof![
                Just("$".to_string()),
                Just("$ ".to_string()),
                Just("$1".to_string()),
                Just("$9x".to_string()),
                Just("${".to_string()),
                Just("${}".to_string()),
                Just("${1}".to_string()),
                Just("${bad-name}".to_string()),
                Just("${ x }".to_string()),
                Just("$$".to_string()),
            ],
            // The trailing separator is non-name so it can never glue onto the
            // stray `$` and form a real (unresolved) variable reference.
            around in (
                "[a-z]{0,8}",
                prop_oneof![
                    Just(String::new()),
                    Just("/".to_string()),
                    Just("-".to_string()),
                    Just(".".to_string()),
                ],
            ),
        ) {
            let state = RunState::default();
            let template = format!("{}{}{}", around.0, stray, around.1);
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(out.contains('$'), "the literal `$` must survive: {out:?}");
        }

        /// An unresolved reference is a hard error that names the variable
        /// (never a silent empty expansion).
        #[test]
        fn unresolved_reference_names_the_variable(name in "[A-Za-z_][A-Za-z0-9_]{0,10}") {
            let state = RunState::default();
            match interpolate(&format!("x/${{{name}}}"), &state) {
                Err(InterpolateError::Unresolved { var, .. }) => prop_assert_eq!(var, name),
                other => return Err(TestCaseError::fail(format!("expected Unresolved, got {other:?}"))),
            }
        }

        /// Interpolating an already-interpolated path is a no-op, so a path
        /// that round-trips through run state twice cannot double-expand.
        #[test]
        fn interpolation_is_idempotent(
            name in "[A-Za-z_][A-Za-z0-9_]{0,10}",
            value in "[a-z0-9/_-]{1,12}",
        ) {
            let mut state = RunState::default();
            state.vars.insert(name.clone(), value);
            let once = interpolate(&format!("/opt/${{{name}}}/${name}"), &state)
                .map_err(|e| TestCaseError::fail(e.to_string()))?;
            let twice = interpolate(&once, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(once, twice);
        }

        /// Interpolation agrees with a hand-built expectation for an arbitrary
        /// sequence of literal and `${VAR}` segments.
        #[test]
        fn interpolation_matches_manual_construction(
            parts in proptest::collection::vec(
                ("[a-z]{1,6}", "[A-Z][A-Z0-9_]{0,5}", "[a-z0-9]{1,8}"),
                1..6,
            ),
        ) {
            let mut state = RunState::default();
            let mut template = String::new();
            let mut expected = String::new();
            for (lit, name, value) in parts {
                // First definition wins, so `expected` and the render agree
                // even when a name repeats across segments.
                let stored = state.vars.entry(name.clone()).or_insert(value);
                template.push_str(&lit);
                template.push_str(&format!("${{{name}}}"));
                expected.push_str(&lit);
                expected.push_str(stored.as_str());
            }
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(out, expected);
        }

        /// Non-ASCII text is preserved byte-for-byte, and a `$` that is not
        /// followed by a valid name stays literal.
        #[test]
        fn non_ascii_survives_interpolation(
            text in "[\\p{L}\\p{N} ]{0,20}",
            // Latin-1 supplement letters: valid UTF-8, never an ASCII name
            // character, so `$` + these stays a literal `$`.
            tail in "[\u{00C0}-\u{017F}]{1,4}",
        ) {
            let state = RunState::default();
            let plain = interpolate(&text, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&plain, &text);
            let template = format!("${tail}");
            let out = interpolate(&template, &state).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(&out, &template);
        }

        /// A group resolves to exactly its member count, in declaration order,
        /// and a `--target` restriction never expands that set.
        #[test]
        fn group_resolution_is_exact(
            count in 1_usize..6,
            keep in 1_usize..6,
        ) {
            let keep = keep.min(count);
            let mut script = String::new();
            let mut members = String::new();
            for i in 0..count {
                script.push_str(&format!("# @server web{i} deploy@10.0.0.{i}\n"));
                if i > 0 {
                    members.push(',');
                }
                members.push_str(&format!("web{i}"));
            }
            script.push_str(&format!("# @group web {members}\n"));
            let plan = parse_script(&script).map_err(|e| TestCaseError::fail(e.to_string()))?;

            let all = resolve_hosts(&plan, &Target::new("web"), &[]).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(all.len(), count);
            for (i, host) in all.iter().enumerate() {
                prop_assert_eq!(&host.alias, &format!("web{i}"));
            }

            let restricted = resolve_hosts(
                &plan,
                &Target::new("web"),
                &["web0".to_string()],
            )
            .map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(restricted.len(), 1);
            prop_assert!(keep >= 1, "sanity: keep is at least 1");
        }

        /// Re-parsing a parsed payload yields the same payload: the scanner is
        /// idempotent, so a plan can be round-tripped through the parser
        /// without drift.
        #[test]
        fn reparse_is_idempotent(
            body in "[a-z]{1,8}( [a-z]{1,8}){0,4}",
        ) {
            let script = format!("# @local\n{body}\n");
            let plan = parse_script(&script).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let first = match &plan.steps[0] {
                Step::Local(local) => local.script.clone(),
                other => return Err(TestCaseError::fail(format!("expected a local step, got {other:?}"))),
            };
            let round = format!("# @local\n{first}");
            let reparsed = parse_script(&round).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let second = match &reparsed.steps[0] {
                Step::Local(local) => local.script.clone(),
                other => return Err(TestCaseError::fail(format!("expected a local step, got {other:?}"))),
            };
            prop_assert_eq!(second, first);
        }

        /// `resolve_hosts` returns the same hosts in the same order for a
        /// fixed plan, however many times it is called: the resolution order
        /// is a property of the plan, not of the call.
        #[test]
        fn resolve_hosts_is_deterministic(
            count in 1_usize..6,
        ) {
            let mut script = String::new();
            let mut members = String::new();
            for i in 0..count {
                script.push_str(&format!("# @server web{i} deploy@10.0.0.{i}\n"));
                if i > 0 {
                    members.push(',');
                }
                members.push_str(&format!("web{i}"));
            }
            script.push_str(&format!("# @group web {members}\n"));
            let plan = parse_script(&script).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let target = Target::new("web");

            let first = resolve_hosts(&plan, &target, &[]).map_err(|e| TestCaseError::fail(e.to_string()))?;
            let second = resolve_hosts(&plan, &target, &[]).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(first.clone(), second);

            let aliases: Vec<&str> = first.iter().map(|h| h.alias.as_str()).collect();
            let expected: Vec<String> = (0..count).map(|i| format!("web{i}")).collect();
            prop_assert_eq!(aliases, expected.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }

    use proptest::{
        prelude::{Just, TestCaseError, prop_assert, prop_assert_eq},
        prop_oneof,
    };

    #[test]
    fn every_active_state_round_trips_through_its_spelling() {
        // Both directions matter: `parse` decides what a playbook may say, and
        // `as_str` is what the generated `systemctl is-active` comparison
        // matches against. A typo in either one is a silently failing check.
        let all = [
            ActiveState::Active,
            ActiveState::Reloading,
            ActiveState::Inactive,
            ActiveState::Failed,
            ActiveState::Activating,
            ActiveState::Deactivating,
        ];
        for state in all {
            assert_eq!(ActiveState::parse(state.as_str()), Some(state), "{state:?}");
        }
        for spelling in
            ActiveState::legal().split(", ").map(|part| part.strip_prefix("or ").unwrap_or(part))
        {
            assert!(ActiveState::parse(spelling).is_some(), "{spelling} must parse");
        }
        assert_eq!(ActiveState::parse("banana"), None);
    }

    #[test]
    fn every_enabled_state_round_trips_through_its_spelling() {
        let all = [
            EnabledState::Enabled,
            EnabledState::Disabled,
            EnabledState::Static,
            EnabledState::Masked,
        ];
        for state in all {
            assert_eq!(EnabledState::parse(state.as_str()), Some(state), "{state:?}");
        }
        for spelling in
            EnabledState::legal().split(", ").map(|part| part.strip_prefix("or ").unwrap_or(part))
        {
            assert!(EnabledState::parse(spelling).is_some(), "{spelling} must parse");
        }
        assert_eq!(EnabledState::parse("enabled-runtime"), None);
    }
}
