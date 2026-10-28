//! Command-line interface definition (clap derive).
//!
//! `shellflow` is a multi-command CLI. The bare positional form
//! (`shellflow deploy.sh`) keeps working and is equivalent to
//! `shellflow run deploy.sh` — the `run` subcommand is the default.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

/// Env var that overrides the default `@secrets` masking threshold.
const MASK_MIN_LEN_ENV: &str = "SHELLFLOW_MASK_MIN_LEN";

/// The built-in default minimum length of a `@secrets` value that is masked.
///
/// `mask_line` does a global substring replacement, so masking a very short
/// value would shred unrelated output; values below the threshold are left
/// alone.
const DEFAULT_MASK_MIN_LEN: usize = 6;

/// The default `@secrets` masking threshold: `$SHELLFLOW_MASK_MIN_LEN` when it
/// holds a valid non-negative integer, otherwise [`DEFAULT_MASK_MIN_LEN`].
///
/// An unparsable value is ignored rather than fatal, so a typo in the
/// environment cannot break a deploy.
#[must_use]
pub(crate) fn default_mask_min_len() -> usize {
    std::env::var(MASK_MIN_LEN_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_MASK_MIN_LEN)
}

/// The default number of hosts a step may fan out to at once.
///
/// A fleet of sixty machines must not open sixty SSH connections at once:
/// that exhausts the server's `MaxStartups`, the operator's file
/// descriptors, and the target's process table, and the resulting failures
/// look like flaky hosts rather than a self-inflicted stampede. `0` (an
/// explicit `--parallel 0`) still means unlimited.
pub(crate) const DEFAULT_PARALLEL: usize = 16;

/// Output mode for concurrent host logs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum OutputMode {
    /// Print every line as it arrives (default).
    #[default]
    Stream,
    /// Buffer each host's lines and print them as a block when the host
    /// finishes.
    Grouped,
}

/// Which transport a command step takes to its host.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum TransportArg {
    /// Muxy where a compatible server answers, ssh everywhere else (default).
    #[default]
    Auto,
    /// Every command step through muxy; fail fast when it is unavailable.
    Muxy,
    /// Never attempt muxy.
    Ssh,
}

impl std::fmt::Display for TransportArg {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(formatter, "auto"),
            Self::Muxy => write!(formatter, "muxy"),
            Self::Ssh => write!(formatter, "ssh"),
        }
    }
}

/// Flags shared by the `run` and `deploy` subcommands.
#[derive(Debug, Args, Clone, Default)]
pub(crate) struct RunFlags {
    /// Increase verbosity: -v info, -vv show commands + payloads,
    /// -vvv inject `set -x` tracing and `ssh -v`.
    #[arg(short, long, action = ArgAction::Count)]
    pub verbose: u8,

    /// Simulate without making changes (syntax-checks payloads, rsync --dry-run).
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Show itemized file changes; implies no writes.
    #[arg(short = 'd', long)]
    pub diff: bool,

    /// Restrict execution to these servers/groups (comma-separated).
    #[arg(short = 't', long, value_name = "TARGET")]
    pub target: Option<String>,

    /// Run only matching blocks (by name or 1-based index).
    #[arg(short = 'o', long, value_name = "STEP")]
    pub only: Vec<String>,

    /// Skip matching blocks (by name or 1-based index).
    #[arg(short = 's', long, value_name = "STEP")]
    pub skip: Vec<String>,

    /// Max concurrent hosts per step.
    ///
    /// `0` means unlimited. The default is a bounded fan-out: a fleet of
    /// sixty machines must not open sixty SSH connections at once, which
    /// exhausts the server's `MaxStartups` and the operator's file
    /// descriptors alike.
    #[arg(short = 'p', long, value_name = "N", default_value_t = DEFAULT_PARALLEL)]
    pub parallel: usize,

    /// Continue after a failed host/step; print a summary.
    #[arg(short = 'c', long)]
    pub continue_on_error: bool,

    /// Syntax-check only: local `bash -n`, remote `bash -n -s`; no execution.
    #[arg(short = 'k', long)]
    pub check: bool,

    /// Per-step timeout in seconds for all steps (overridable by @timeout).
    #[arg(long, value_name = "SECS")]
    pub timeout: Option<u64>,

    /// Output mode for concurrent host logs.
    #[arg(long, value_enum, value_name = "MODE", default_value_t = OutputMode::Stream)]
    pub output: OutputMode,

    /// Run remote blocks and copies on the local machine instead of over SSH
    /// (local debugging; no network or sudo required).
    #[arg(long)]
    pub local: bool,

    /// Age identity file for `@secrets` / `deploy` decryption.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Reuse SSH connections within a run (ControlMaster).
    ///
    /// On by default: a playbook is a sequence of steps against the same
    /// hosts, and every step used to pay a full TCP connect plus key
    /// exchange. With `ControlMaster=auto` OpenSSH reuses the connection
    /// when it can and falls back to a fresh one when it cannot — a dead
    /// control socket is detected and replaced, so it cannot break a deploy.
    #[arg(long, default_value_t = true)]
    pub ssh_reuse: bool,

    /// Do not reuse SSH connections within a run.
    ///
    /// Every step then opens its own connection, which costs a TCP connect
    /// and a key exchange per step.
    #[arg(long)]
    pub no_ssh_reuse: bool,

    /// Allow a copy step to fall back to `scp` on a host without `rsync`,
    /// dropping `--delete` and `--exclude`.
    ///
    /// Off by default: the fallback cannot mirror deletions or filter files,
    /// so it silently performs a *different* transfer than the playbook
    /// asked for. With this flag the downgrade is accepted explicitly.
    #[arg(long)]
    pub allow_unfiltered_copy: bool,

    /// Minimum value length to mask for values sourced from `@secrets` files.
    ///
    /// Defaults to `$SHELLFLOW_MASK_MIN_LEN`, or 6 when that is unset or
    /// unparsable.
    #[arg(long, value_name = "N")]
    pub mask_min_len: Option<usize>,

    /// Append every streamed run line (tagged [host] + stream) to this file.
    ///
    /// Only the `run` path produces those lines, so the flag lives here and
    /// not on the global set: the other subcommands used to accept it and
    /// silently ignore it.
    #[arg(short = 'l', long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Which transport a command step takes to its host.
    ///
    /// `auto` (default) uses muxy where a compatible server answers and ssh
    /// everywhere else, never failing a green run because of muxy; `muxy`
    /// routes every command step through muxy and fails fast (exit 3) when a
    /// selected host cannot do it; `ssh` never attempts muxy.
    #[arg(long, value_enum, value_name = "MODE")]
    pub transport: Option<TransportArg>,

    /// Alias for `--transport ssh`, for muscle memory.
    #[arg(long)]
    pub no_muxy: bool,

    /// Leave a cancelled step's muxy session running instead of ending it.
    #[arg(long)]
    pub muxy_keep: bool,

    /// Muxy session width in columns (default 200, max 4096).
    #[arg(long, value_name = "N")]
    pub muxy_cols: Option<u16>,

    /// Muxy session height in rows (default 50, max 1024).
    #[arg(long, value_name = "N")]
    pub muxy_rows: Option<u16>,
}

/// Arguments for the `run` subcommand (also the default).
#[derive(Debug, Args, Clone)]
pub(crate) struct RunArgs {
    /// Deploy script path.
    #[arg(value_name = "SCRIPT", default_value = "deploy.sh")]
    pub script: PathBuf,

    /// Shared execution flags.
    #[command(flatten)]
    pub flags: RunFlags,
}

/// Arguments for `shellflow keys`.
#[derive(Debug, Args)]
pub(crate) struct KeysArgs {
    #[command(subcommand)]
    pub command: KeysCmd,
}

/// The `keys` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum KeysCmd {
    /// Generate a new age identity and write it to a file (refuses to
    /// overwrite an existing file).
    Generate(KeysGenerateArgs),
    /// Print the `age1…` public key for an identity.
    Public(KeysPublicArgs),
}

/// Arguments for `keys generate`.
#[derive(Debug, Args)]
pub(crate) struct KeysGenerateArgs {
    /// Output path for the identity file.
    #[arg(short = 'o', long, value_name = "PATH", default_value = "~/.config/age/keys.txt")]
    pub output: PathBuf,
}

/// Arguments for `keys public`.
#[derive(Debug, Args)]
pub(crate) struct KeysPublicArgs {
    /// Identity file to read.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,
}

/// Arguments for `shellflow secret`.
#[derive(Debug, Args)]
pub(crate) struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretCmd,
}

/// The `secret` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum SecretCmd {
    /// Encrypt a plaintext env file to the given recipients.
    Encrypt(SecretEncryptArgs),
    /// Decrypt an age file to stdout (or `-o PATH`).
    Decrypt(SecretDecryptArgs),
    /// Decrypt, open `$EDITOR`, and re-encrypt to the given recipients.
    Edit(SecretEditArgs),
    /// Print the `ImportCredential=KEY` lines for an env file (`--store-dir`
    /// switches to the per-service `LoadCredentialEncrypted=KEY:PATH` form).
    Creds(SecretCredsArgs),
    /// Check that every `<host>.env.age` in a service directory shares the
    /// same key set (units are shared across hosts, so drift breaks deploys).
    KeysCheck(SecretKeysCheckArgs),
    /// Find identical credential *values* shared across files (by hash —
    /// values are never printed). Shared values mean shared rotation:
    /// rotating one file without the others silently breaks the rest.
    FindDuplicates(SecretFindDuplicatesArgs),
}

/// Arguments for `secret keys-check`.
#[derive(Debug, Args)]
pub(crate) struct SecretKeysCheckArgs {
    /// Identity file to decrypt with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Service directory containing `<host>.env.age` files.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
}

/// Arguments for `secret find-duplicates`.
#[derive(Debug, Args)]
pub(crate) struct SecretFindDuplicatesArgs {
    /// Identity file to decrypt with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Directory tree to scan for `*.env.age` files (default: current dir).
    #[arg(value_name = "DIR", default_value = ".")]
    pub dir: PathBuf,
}

/// Arguments for `secret encrypt`.
#[derive(Debug, Args)]
pub(crate) struct SecretEncryptArgs {
    /// Recipient public key (`age1…`); repeatable.
    #[arg(short = 'r', long = "recipient", value_name = "AGE1...")]
    pub recipients: Vec<String>,

    /// Directory of `*.pub` files to load additional recipients from.
    #[arg(long, value_name = "PATH")]
    pub recipients_dir: Option<PathBuf>,

    /// Output path; defaults to stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Plaintext input file; defaults to stdin.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// Arguments for `secret decrypt`.
#[derive(Debug, Args)]
pub(crate) struct SecretDecryptArgs {
    /// Identity file to decrypt with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Output path; defaults to stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Encrypted input file; defaults to stdin.
    #[arg(value_name = "FILE")]
    pub file: Option<PathBuf>,
}

/// Arguments for `secret edit`.
#[derive(Debug, Args)]
pub(crate) struct SecretEditArgs {
    /// Identity file to decrypt with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Recipient public key (`age1…`); repeatable. Required unless
    /// `--recipients-dir` is given — re-encrypting without recipients would
    /// silently drop every operator (age is anonymous, so the original set
    /// cannot be recovered from the file).
    #[arg(
        short = 'r',
        long = "recipient",
        value_name = "AGE1...",
        required_unless_present = "recipients_dir"
    )]
    pub recipients: Vec<String>,

    /// Directory of `*.pub` files to load recipients from.
    #[arg(long, value_name = "PATH")]
    pub recipients_dir: Option<PathBuf>,

    /// The encrypted file to edit.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Arguments for `secret creds`.
#[derive(Debug, Args)]
pub(crate) struct SecretCredsArgs {
    /// Identity file to decrypt with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Print `LoadCredentialEncrypted=KEY:<dir>/<KEY>` lines instead of the default
    /// flat `ImportCredential=KEY` form, for per-service credential stores
    /// (e.g. `/etc/credstore.encrypted/<svc>`).
    #[arg(long, value_name = "PATH")]
    pub store_dir: Option<PathBuf>,

    /// The encrypted env file to read.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Arguments for `shellflow template`.
#[derive(Debug, Args)]
pub(crate) struct TemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCmd,
}

/// The `template` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum TemplateCmd {
    /// Check that every `${KEY}` placeholder in a template exists in an
    /// encrypted env file (the manifest `cred-env render` needs at runtime).
    Check(TemplateCheckArgs),
    /// Decrypt, substitute, and validate a template entirely in memory
    /// (nothing is written). Catches structural accidents — a dropped
    /// newline that joins two TOML lines, an unclosed quote — that `check`
    /// cannot see because it only compares key sets.
    Render(TemplateRenderArgs),
}

/// Arguments for `template check`.
#[derive(Debug, Args)]
pub(crate) struct TemplateCheckArgs {
    /// Identity file to decrypt the env file with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Template file with `${KEY}` placeholders.
    #[arg(value_name = "TEMPLATE")]
    pub template: PathBuf,

    /// Encrypted env file providing the credential keys.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Output format for `template render` validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum RenderFormat {
    /// TOML (also accepts JSON5-ish superset constructs toml_edit tolerates).
    Toml,
    /// Strict JSON.
    Json,
    /// Substitute only; skip structural validation.
    #[default]
    None,
}

/// Arguments for `template render`.
#[derive(Debug, Args)]
pub(crate) struct TemplateRenderArgs {
    /// Identity file to decrypt the env file with.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Validate the rendered output as this format (default: none).
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: RenderFormat,

    /// Template file with `${KEY}` placeholders.
    #[arg(value_name = "TEMPLATE")]
    pub template: PathBuf,

    /// Encrypted env file providing the credential values.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// Arguments for `shellflow emit`.
#[derive(Debug, Args)]
pub(crate) struct EmitArgs {
    #[command(subcommand)]
    pub command: EmitCmd,
}

/// The `emit` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum EmitCmd {
    /// Print (or write) the embedded `cred-env` bash helper.
    ///
    /// Fallback for targets that cannot host the `shellflow` binary; the
    /// primary path is `shellflow cred-env` (same semantics, no shell).
    CredEnv(EmitCredEnvArgs),
}

/// Arguments for `emit cred-env`.
#[derive(Debug, Args)]
pub(crate) struct EmitCredEnvArgs {
    /// Output path (written mode 0755); defaults to stdout.
    #[arg(short = 'o', long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

/// Arguments for `shellflow systemd` — the target-side systemd helpers.
///
/// These subcommands run **on the target host** (the binary is installed once
/// per host by a deploy playbook). They talk to the local systemd only and
/// never open the network.
///
/// `wait` is the reason the helper exists: the whole wait loop runs on the
/// host that owns the unit, so a controller-side wait costs **one** SSH
/// round-trip instead of one per poll. Each poll streams a machine-readable
/// state line (`SFW<TAB>type<TAB>active<TAB>sub<TAB>result<TAB>status`) and
/// the verdict is the exit code (0 ready, 3 failed, 4 timeout, 5 not found).
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdArgs {
    #[command(subcommand)]
    pub command: SystemdCmd,
}

/// The `systemd` subcommands.
#[derive(Clone, Debug, Subcommand)]
pub(crate) enum SystemdCmd {
    /// Send a systemd notification for the unit this process runs in.
    Notify(SystemdNotifyArgs),
    /// Wait for a unit to reach a state (runs on the target host).
    Wait(SystemdWaitArgs),
    /// Trigger a graceful reload and wait for the handshake.
    Reload(SystemdReloadArgs),
    /// Print a unit's state once.
    Status(SystemdStatusArgs),
    /// Stream a unit's state until it becomes ready.
    Watch(SystemdWatchArgs),
    /// Run a command as a transient systemd unit.
    Transient(SystemdTransientArgs),
    /// Run a command under a readiness contract (a `Type=notify` supervisor).
    Exec(SystemdExecArgs),
    /// Keep a unit's watchdog alive.
    Watchdog(SystemdWatchdogArgs),
}

/// What a wait is waiting for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(crate) enum WaitForArg {
    /// The unit is active (or a oneshot that finished successfully).
    Ready,
    /// The unit is active *and* running.
    Running,
}

/// Arguments for `systemd notify`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdNotifyArgs {
    /// Send `READY=1` (the unit finished starting).
    #[arg(long)]
    pub ready: bool,
    /// Send `RELOADING=1` (with `MONOTONIC_USEC`, as systemd >= 253 requires).
    #[arg(long)]
    pub reloading: bool,
    /// Send `STOPPING=1`.
    #[arg(long)]
    pub stopping: bool,
    /// Send `WATCHDOG=1` (the service is still alive).
    #[arg(long)]
    pub watchdog: bool,
    /// Send `STATUS=<text>` (the service's own status line).
    #[arg(long, value_name = "TEXT")]
    pub status: Option<String>,
    /// Send `MAINPID=<pid>`.
    #[arg(long, value_name = "PID")]
    pub main_pid: Option<u32>,
    /// Send a raw `KEY=VALUE` state (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    pub raw: Vec<String>,
}

/// Arguments for `systemd wait`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdWaitArgs {
    /// The unit to wait for.
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// What to wait for.
    #[arg(long = "for", value_enum, default_value_t = WaitForArg::Ready)]
    pub for_: WaitForArg,

    /// How long to wait, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,

    /// Seconds between polls.
    #[arg(long, value_name = "SECS", default_value_t = 5)]
    pub interval: u64,
}

/// Arguments for `systemd reload`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdReloadArgs {
    /// The unit to reload.
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// Send this signal instead of `systemctl reload` (e.g. `SIGUSR1`).
    #[arg(long, value_name = "SIG")]
    pub signal: Option<String>,

    /// Wait for the reload to finish.
    #[arg(long)]
    pub wait: bool,

    /// How long to wait for the handshake, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 120)]
    pub timeout: u64,

    /// Seconds between polls.
    #[arg(long, value_name = "SECS", default_value_t = 2)]
    pub interval: u64,
}

/// Arguments for `systemd status`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdStatusArgs {
    /// The unit to inspect.
    #[arg(value_name = "UNIT")]
    pub unit: String,
}

/// Arguments for `systemd watch`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdWatchArgs {
    /// The unit to watch.
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// How long to watch, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,

    /// Seconds between polls (only used without the `dbus` feature).
    #[arg(long, value_name = "SECS", default_value_t = 5)]
    pub interval: u64,
}

/// Arguments for `systemd transient`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdTransientArgs {
    /// The command to run, with its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CMD"
    )]
    pub command: Vec<String>,

    /// The transient unit name.
    #[arg(long, value_name = "NAME")]
    pub unit: Option<String>,

    /// A unit property to set (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    pub property: Option<String>,

    /// Run the command in a scope instead of a service.
    #[arg(long)]
    pub scope: bool,
}

/// Arguments for `shellflow host` — the target-side host helpers.
///
/// These subcommands run **on the target host** (the binary is installed once
/// per host by a deploy playbook). They own the semantics a playbook used to
/// spell out in shell, with the guarantees the shell spelling did not have:
/// atomic installs, structural backup assertions, and a restart that never
/// starts a unit the operator keeps stopped.
#[derive(Debug, Args)]
pub(crate) struct HostArgs {
    #[command(subcommand)]
    pub command: HostCmd,
}

/// The `host` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum HostCmd {
    /// Drive a systemd unit's lifecycle: verify, enable, restart, wait.
    Service(HostServiceArgs),
    /// Install a file on the target atomically.
    Install(HostInstallArgs),
    /// Snapshot files on the target for rollback.
    Backup(HostBackupArgs),
    /// Seal a service's credential store and check it against the unit.
    Credstore(HostCredstoreArgs),
    /// Assert that no credential value appears in the journal or the argv.
    AssertNoLeak(HostAssertNoLeakArgs),
    /// Assert that a file matches a digest.
    AssertDigest(HostAssertDigestArgs),
    /// Assert that a service's credential store is well formed.
    AssertCredstore(HostAssertCredstoreArgs),
    /// List the units installed on the target.
    Inventory(HostInventoryArgs),
}

/// Arguments for `host service`.
#[derive(Debug, Args)]
pub(crate) struct HostServiceArgs {
    /// The unit to drive (`foo` or `foo.service`).
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// Enable the unit at boot.
    #[arg(long)]
    pub enable: bool,

    /// Restart the unit — but only when it was running.
    #[arg(long)]
    pub restart: bool,

    /// Reload the unit through its own `ExecReload=`.
    #[arg(long)]
    pub reload: bool,

    /// Wait for the unit to become ready.
    #[arg(long)]
    pub wait: bool,

    /// Verify the installed unit before reloading the manager.
    #[arg(long)]
    pub verify: bool,

    /// Start the unit even when it was not running.
    #[arg(long)]
    pub force_start: bool,

    /// How long to wait for readiness, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,
}

/// Parse a file mode, written in octal (`0644`).
///
/// A plain number parser reads `0644` as decimal 644 -- a mode of 0o1204,
/// which is neither readable nor writable by anyone but the owner.
fn parse_octal_mode(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    let parsed = u32::from_str_radix(trimmed, 8)
        .map_err(|err| format!("`{trimmed}` is not an octal file mode: {err}"))?;
    if parsed > 0o7777 {
        return Err(format!("`{trimmed}` is not a file mode"));
    }
    Ok(parsed)
}

/// Arguments for `host install`.
#[derive(Debug, Args)]
pub(crate) struct HostInstallArgs {
    /// The source path on the target.
    #[arg(value_name = "SRC")]
    pub src: String,

    /// The destination path on the target.
    #[arg(value_name = "DST")]
    pub dst: String,

    /// The file mode, in octal (e.g. `0644`).
    #[arg(long, value_name = "MODE", value_parser = parse_octal_mode)]
    pub mode: Option<u32>,

    /// The `user:group` that owns the file.
    #[arg(long, value_name = "USER[:GROUP]")]
    pub owner: Option<String>,

    /// The mode of the destination directory, created when missing.
    #[arg(long, value_name = "MODE", value_parser = parse_octal_mode)]
    pub dir_mode: Option<u32>,
}

/// Arguments for `host backup`.
#[derive(Debug, Args)]
pub(crate) struct HostBackupArgs {
    /// The paths to snapshot on the target.
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<String>,

    /// The service name the snapshot belongs to.
    #[arg(long, value_name = "NAME")]
    pub service: Option<String>,

    /// The snapshot directory (default `/root/<service>-backup-<stamp>`).
    #[arg(long, value_name = "DIR")]
    pub dir: Option<String>,

    /// How many snapshots to keep.
    #[arg(long, value_name = "N")]
    pub keep: Option<u32>,

    /// Encrypt the snapshot with the host key, so no plaintext lands on disk.
    #[arg(long)]
    pub seal: bool,
}

/// Arguments for `host credstore`.
#[derive(Debug, Args)]
pub(crate) struct HostCredstoreArgs {
    /// The service name (the credential-store directory name).
    #[arg(value_name = "SERVICE")]
    pub service: String,

    /// Credential keys that must be present (comma-separated).
    #[arg(long, value_name = "KEY,…")]
    pub require: Vec<String>,
}

/// Arguments for `host assert-no-leak`.
#[derive(Debug, Args)]
pub(crate) struct HostAssertNoLeakArgs {
    /// The unit whose journal and argv are scanned.
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// How many journal lines to scan.
    #[arg(long, value_name = "N", default_value_t = 200)]
    pub lines: u64,
}

/// Arguments for `host assert-digest`.
#[derive(Debug, Args)]
pub(crate) struct HostAssertDigestArgs {
    /// The file to check.
    #[arg(value_name = "PATH")]
    pub path: String,

    /// The expected sha256 digest.
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,

    /// A local file to compare against.
    #[arg(long, value_name = "PATH")]
    pub local: Option<String>,
}

/// Arguments for `host assert-credstore`.
#[derive(Debug, Args)]
pub(crate) struct HostAssertCredstoreArgs {
    /// The service name (the credential-store directory name).
    #[arg(value_name = "SERVICE")]
    pub service: String,
}

/// Arguments for `host inventory`.
#[derive(Debug, Args)]
pub(crate) struct HostInventoryArgs {}

/// Arguments for `systemd exec` — the readiness supervisor.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdExecArgs {
    /// The command to supervise, with its arguments.
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CMD"
    )]
    pub command: Vec<String>,

    /// The port that must accept connections before the unit is ready.
    #[arg(long, value_name = "PORT")]
    pub ready_port: Option<u16>,

    /// The URL that must answer before the unit is ready.
    #[arg(long, value_name = "URL")]
    pub ready_url: Option<String>,

    /// The file that must exist before the unit is ready.
    #[arg(long, value_name = "PATH")]
    pub ready_file: Option<String>,

    /// How long to wait for readiness, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    pub timeout: u64,

    /// Keep the unit's watchdog alive on the child's behalf.
    #[arg(long)]
    pub watchdog: bool,

    /// Seconds between watchdog pings.
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    pub watchdog_interval: u64,

    /// The status text to publish once the service is ready.
    #[arg(long, value_name = "TEXT")]
    pub status: Option<String>,
}

/// Arguments for `systemd watchdog`.
#[derive(Clone, Debug, Args)]
pub(crate) struct SystemdWatchdogArgs {
    /// Seconds between pings.
    #[arg(long, value_name = "SECS", default_value_t = 10)]
    pub interval: u64,

    /// How long to keep pinging, in seconds.
    #[arg(long, value_name = "SECS", default_value_t = 3600)]
    pub timeout: u64,
}

/// Arguments for `shellflow unit` — the unit generator.
#[derive(Debug, Args)]
pub(crate) struct UnitArgs {
    #[command(subcommand)]
    pub command: UnitCmd,
}

/// The `unit` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum UnitCmd {
    /// Generate a service's drop-in from its manifest.
    Render(UnitRenderArgs),
    /// Print a service's manifest.
    Manifest(UnitManifestArgs),
    /// Check the repository's consistency: the generated drop-ins, the
    /// install steps, and the shared hardening.
    Verify(UnitVerifyArgs),
}

/// Arguments for `unit render`.
#[derive(Debug, Args)]
pub(crate) struct UnitRenderArgs {
    /// The service to render (`services/<svc>/`).
    #[arg(value_name = "SERVICE")]
    pub service: String,

    /// The unit to render (`services/<svc>/<unit>.service.toml`).
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// The repository root (default: the current directory).
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,

    /// Where to write the drop-in (default: `services/<svc>/<unit>.service.d/`).
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Print the drop-in instead of writing it.
    #[arg(long)]
    pub stdout: bool,

    /// Check that the drop-in on disk is up to date; exit non-zero when it is
    /// not, without writing anything.
    #[arg(long)]
    pub check: bool,

    /// The age identity for reading the credential key set.
    #[arg(long, value_name = "PATH")]
    pub identity: Option<PathBuf>,
}

/// Arguments for `unit verify`.
#[derive(Debug, Args)]
pub(crate) struct UnitVerifyArgs {
    /// The repository root (default: the current directory).
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,
}

/// Arguments for `unit manifest`.
#[derive(Debug, Args)]
pub(crate) struct UnitManifestArgs {
    /// The service to read (`services/<svc>/`).
    #[arg(value_name = "SERVICE")]
    pub service: String,

    /// The unit to read (`services/<svc>/<unit>.service.toml`).
    #[arg(value_name = "UNIT")]
    pub unit: String,

    /// The repository root (default: the current directory).
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,
}

/// Arguments for `shellflow cred-env` — the target-side credential helpers.
///
/// These subcommands run **on the target host** (the binary is installed once
/// per host by a deploy playbook). They never touch age identities, never
/// open the network, and read only `$CREDENTIALS_DIRECTORY` plus the
/// environment a playbook block already injected.
#[derive(Debug, Args)]
pub(crate) struct CredEnvArgs {
    #[command(subcommand)]
    pub command: CredEnvCmd,
}

/// The `cred-env` subcommands.
#[derive(Debug, Subcommand)]
pub(crate) enum CredEnvCmd {
    /// Export every credential in `$CREDENTIALS_DIRECTORY` as an environment
    /// variable (filename = variable name) and exec the command.
    Exec(CredEnvExecArgs),
    /// Substitute `${KEY}` placeholders in a template with credential values
    /// and write the result (0600, atomic rename).
    Render(CredEnvRenderArgs),
    /// Install credentials into a per-service host-key-bound store via
    /// `systemd-creds` (runs on the target; values come from the environment).
    CredstoreInstall(CredstoreInstallArgs),
}

/// Arguments for `cred-env exec`.
#[derive(Debug, Args)]
pub(crate) struct CredEnvExecArgs {
    /// The command to run, with its arguments. Everything after `exec` is
    /// passed through verbatim (flags included).
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required = true,
        value_name = "CMD"
    )]
    pub command: Vec<String>,
}

/// Arguments for `cred-env render`.
#[derive(Debug, Args)]
pub(crate) struct CredEnvRenderArgs {
    /// Template file with `${KEY}` placeholders (plaintext, no secrets).
    #[arg(value_name = "TMPL")]
    pub template: PathBuf,

    /// Output path; its parent directory must exist (created 0600).
    #[arg(value_name = "OUT")]
    pub output: PathBuf,
}

/// Arguments for `cred-env credstore-install`.
#[derive(Debug, Args)]
pub(crate) struct CredstoreInstallArgs {
    /// Service name; the default store is `/etc/credstore.encrypted/<SVC>`.
    #[arg(value_name = "SVC")]
    pub service: String,

    /// Override the store directory (default `/etc/credstore.encrypted/<SVC>`).
    #[arg(long, value_name = "PATH")]
    pub store_dir: Option<PathBuf>,
}

/// Arguments for `shellflow service` — repository scaffolding.
#[derive(Debug, Args)]
pub(crate) struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCmd,
}

/// Arguments for `shellflow audit`.
#[derive(Debug, Args)]
pub(crate) struct AuditArgs {
    /// Repository root to scan (default: current directory).
    #[arg(value_name = "PATH", default_value = ".")]
    pub path: PathBuf,
}
/// The `service` subcommands.
#[derive(Debug, Clone, Subcommand)]
pub(crate) enum ServiceCmd {
    /// Scaffold a new service in the flat layout (config template, systemd
    /// unit, deploy playbook skeleton) in the current repository.
    Init(ServiceInitArgs),
    /// Audit a deployed systemd unit over SSH (read-only): argv/env secret
    /// exposure, credential wiring, listening sockets, journal leak scan.
    Check(ServiceCheckArgs),
    /// Compare a file in the repository with the file the target runs;
    /// exits non-zero when they differ (drift).
    Diff(ServiceDiffArgs),
    /// Print the sha256 manifest of a deployed tree.
    Manifest(ServiceManifestArgs),
    /// Verify a deployed tree against a saved sha256 manifest; exits
    /// non-zero when the host drifted from it.
    Verify(ServiceVerifyArgs),
    /// The fleet view: the state of every service on every host.
    Status(ServiceStatusArgs),
}

/// Scaffold pattern: which credential/deployment shape to generate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, clap::ValueEnum)]
pub(crate) enum ServicePattern {
    /// Config-file render + env export (third-party apps reading files).
    #[default]
    Full,
    /// Env export only, no config template (apps reading env vars).
    Exec,
    /// No secrets at all (verbatim unit takeover + management playbook).
    NoSecret,
    /// Podman quadlet container with env-file render.
    Container,
    /// One-shot task (+ optional `--timer` schedule).
    Oneshot,
    /// Verbatim takeover that never starts the unit (dormant strategies).
    NoStart,
    /// Readiness over `sd_notify` (Type=notify) with a graceful reload.
    Notify,
    /// Socket-activated: systemd owns the port, the service inherits the fd.
    Socket,
}

/// Arguments for `service init`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceInitArgs {
    /// Service name (`[a-z][a-z0-9-]*`).
    #[arg(value_name = "SVC")]
    pub service: String,

    /// Host alias this service deploys to (repeatable; default `api`).
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,

    /// Scaffold pattern (default: full).
    #[arg(long, value_enum, value_name = "PATTERN", default_value_t = ServicePattern::Full)]
    pub pattern: ServicePattern,

    /// For `--pattern oneshot`: also scaffold a timer with this schedule.
    #[arg(long, value_name = "SCHEDULE")]
    pub timer: Option<String>,
}

/// Arguments for `service check`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceCheckArgs {
    /// Service name (systemd unit `<svc>.service` on the target).
    ///
    /// Omit it with `--all` to audit every service of the host.
    #[arg(value_name = "SVC")]
    pub service: Option<String>,

    /// SSH target (alias, `[user@]host[:port]`, or `~/.ssh/config` entry).
    #[arg(long = "host", value_name = "HOST")]
    pub host: String,

    /// Also grep this many journal lines for secret-value shapes (default 50).
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub journal_lines: usize,

    /// Audit every service of the host, in one round trip.
    #[arg(long)]
    pub all: bool,

    /// The repository root, for the service manifests (default: the current
    /// directory).
    #[arg(long, value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,
}

/// Arguments for `service diff`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceDiffArgs {
    /// Service name: compares the repository's unit with the deployed one.
    ///
    /// Omit it and give `--local`/`--remote` pairs instead.
    #[arg(value_name = "SVC")]
    pub service: Option<String>,

    /// SSH target (alias, `[user@]host[:port]`, or `~/.ssh/config` entry).
    #[arg(long = "host", value_name = "HOST")]
    pub host: String,

    /// Local file to compare (pair with `--remote`, in order).
    #[arg(long = "local", value_name = "PATH")]
    pub local: Vec<String>,

    /// Remote file to compare (pair with `--local`, in order).
    #[arg(long = "remote", value_name = "PATH")]
    pub remote: Vec<String>,

    /// Repository root that holds `services/<svc>/` (default: current
    /// directory).
    #[arg(long = "repo", value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,

    /// Report the drift without printing the diff.
    #[arg(long)]
    pub quiet: bool,
}

/// Arguments for `service manifest`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceManifestArgs {
    /// SSH target (alias, `[user@]host[:port]`, or `~/.ssh/config` entry).
    #[arg(long = "host", value_name = "HOST")]
    pub host: String,

    /// Remote directory or file to fingerprint (repeatable).
    #[arg(long = "path", value_name = "PATH")]
    pub paths: Vec<String>,

    /// Write the manifest here instead of stdout.
    #[arg(long = "output", value_name = "PATH")]
    pub output: Option<PathBuf>,
}

/// Arguments for `service status`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceStatusArgs {
    /// Every host the repository's playbooks declare (with `--all`).
    #[arg(long)]
    pub all: bool,

    /// Host to report on (repeatable).
    #[arg(long = "host", value_name = "HOST")]
    pub hosts: Vec<String>,

    /// Service to report on (repeatable); default: every service in
    /// `services/`.
    #[arg(long = "service", value_name = "SVC")]
    pub services: Vec<String>,

    /// Repository root that describes the fleet (default: current
    /// directory).
    #[arg(long = "repo", value_name = "PATH", default_value = ".")]
    pub repo: PathBuf,
}

/// Arguments for `service verify`.
#[derive(Debug, Clone, Args)]
pub(crate) struct ServiceVerifyArgs {
    /// SSH target (alias, `[user@]host[:port]`, or `~/.ssh/config` entry).
    #[arg(long = "host", value_name = "HOST")]
    pub host: String,

    /// The manifest to verify against.
    #[arg(long = "manifest", value_name = "PATH")]
    pub manifest: PathBuf,

    /// Also verify these paths even if the manifest does not list them.
    #[arg(long = "path", value_name = "PATH")]
    pub paths: Vec<String>,
}

/// Flags shared by every subcommand.
///
/// `--no-color` is declared once, at the top level, and marked `global`: clap
/// propagates it to every subcommand, so it can be given before *or* after
/// the subcommand name.
#[derive(Debug, Clone, Default, Args)]
pub(crate) struct GlobalFlags {
    /// Disable ANSI colors.
    #[arg(long, global = true)]
    pub no_color: bool,
}

/// The top-level CLI: a `run` subcommand (also the default via the bare
/// positional `SCRIPT`), plus `keys`, `secret`, `template`, and `emit`.
#[derive(Debug, Parser)]
#[command(name = "shellflow", version, about, long_about)]
pub(crate) struct Cli {
    /// Flags that apply to every subcommand.
    #[command(flatten)]
    pub globals: GlobalFlags,

    /// The default `run` arguments (active when no subcommand is given).
    #[command(flatten)]
    pub run: RunArgs,

    /// Optional subcommand.
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// The subcommands of `shellflow`.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run a deploy script (default).
    Run(RunArgs),
    /// Manage age identities.
    Keys(KeysArgs),
    /// Encrypt, decrypt, and edit age-encrypted env files.
    Secret(SecretArgs),
    /// Cross-check `${KEY}` templates against encrypted env files.
    Template(TemplateArgs),
    /// Print embedded target-side helper assets (bash fallback).
    Emit(EmitArgs),
    /// Target-side credential helpers (run on the target host).
    CredEnv(CredEnvArgs),
    /// Target-side systemd helpers (run on the target host).
    Systemd(SystemdArgs),
    /// Target-side host helpers (run on the target host).
    Host(HostArgs),
    /// Scaffold new services in the flat repository layout.
    Service(ServiceArgs),
    /// Generate unit drop-ins from the service manifests.
    Unit(UnitArgs),
    /// Scan a repository for secret-shaped plaintext (pre-commit gate).
    Audit(AuditArgs),
}

impl RunArgs {
    /// The parsed `--target` restriction list.
    #[must_use]
    pub(crate) fn target_restrict(&self) -> Vec<String> {
        self.flags.target.as_deref().map_or_default(|t| {
            t.split(',').map(str::trim).filter(|s| !s.is_empty()).map(ToOwned::to_owned).collect()
        })
    }

    /// The effective `@secrets` masking threshold: an explicit
    /// `--mask-min-len`, else `$SHELLFLOW_MASK_MIN_LEN`, else 6.
    #[must_use]
    pub(crate) fn mask_min_len(&self) -> usize {
        self.flags.mask_min_len.unwrap_or_else(default_mask_min_len)
    }

    /// The effective transport: `--no-muxy` wins, then `--transport`, then
    /// `$SHELLFLOW_TRANSPORT`, else `auto`.
    #[must_use]
    pub(crate) fn effective_transport(&self) -> TransportArg {
        if self.flags.no_muxy {
            return TransportArg::Ssh;
        }
        if let Some(transport) = self.flags.transport {
            return transport;
        }
        match std::env::var("SHELLFLOW_TRANSPORT").as_deref() {
            Ok("muxy") => TransportArg::Muxy,
            Ok("ssh") => TransportArg::Ssh,
            _ => TransportArg::Auto,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command};

    #[test]
    fn bare_script_is_treated_as_run() {
        let cli = Cli::parse_from(["shellflow", "deploy.sh"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.run.script.to_string_lossy(), "deploy.sh");
    }

    #[test]
    fn default_script() {
        let cli = Cli::parse_from(["shellflow"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.run.script.to_string_lossy(), "deploy.sh");
    }

    #[test]
    fn parses_verbose_counts() {
        let cli = Cli::parse_from(["shellflow", "-vvv", "deploy.sh"]);
        assert!(cli.command.is_none());
        assert_eq!(cli.run.flags.verbose, 3);
    }

    #[test]
    fn parses_target_restrict() {
        let cli = Cli::parse_from(["shellflow", "-t", "web1, web2"]);
        assert_eq!(cli.run.target_restrict(), vec!["web1", "web2"]);
    }

    #[test]
    fn explicit_run_subcommand() {
        let cli = Cli::parse_from(["shellflow", "run", "playbook.sh", "-t", "web1"]);
        match cli.command {
            Some(Command::Run(args)) => {
                assert_eq!(args.script.to_string_lossy(), "playbook.sh");
                assert_eq!(args.target_restrict(), vec!["web1"]);
            }
            other => panic!("expected run subcommand, got {other:?}"),
        }
    }

    #[test]
    fn keys_subcommand() {
        let cli = Cli::parse_from(["shellflow", "keys", "generate", "-o", "/tmp/k.txt"]);
        match cli.command {
            Some(Command::Keys(keys)) => match keys.command {
                super::KeysCmd::Generate(g) => {
                    assert_eq!(g.output.to_string_lossy(), "/tmp/k.txt");
                }
                super::KeysCmd::Public(_) => panic!("expected generate subcommand"),
            },
            other => panic!("expected keys subcommand, got {other:?}"),
        }
    }

    #[test]
    fn local_flag_parses() {
        let cli = Cli::parse_from(["shellflow", "--local", "deploy.sh"]);
        assert!(cli.command.is_none());
        assert!(cli.run.flags.local);
    }

    #[test]
    fn ssh_reuse_is_on_by_default() {
        let cli = Cli::parse_from(["shellflow", "deploy.sh"]);
        assert!(cli.run.flags.ssh_reuse);
        assert!(!cli.run.flags.no_ssh_reuse);
    }

    #[test]
    fn ssh_reuse_can_be_turned_off() {
        let cli = Cli::parse_from(["shellflow", "--no-ssh-reuse", "deploy.sh"]);
        assert!(cli.run.flags.no_ssh_reuse);
    }

    #[test]
    fn creds_store_dir_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "secret",
            "creds",
            "--store-dir",
            "/etc/credstore.encrypted/zenoh",
            "services/zenoh/api.env.age",
        ]);
        match cli.command {
            Some(Command::Secret(secret)) => match secret.command {
                super::SecretCmd::Creds(c) => {
                    assert_eq!(
                        c.store_dir.map(|p| p.to_string_lossy().into_owned()),
                        Some("/etc/credstore.encrypted/zenoh".to_string())
                    );
                    assert_eq!(c.file.to_string_lossy(), "services/zenoh/api.env.age");
                }
                other => panic!("expected creds subcommand, got {other:?}"),
            },
            other => panic!("expected secret subcommand, got {other:?}"),
        }
    }

    #[test]
    fn cred_env_exec_passes_through_flags() {
        // Everything after `exec` belongs to the wrapped command, flags
        // included — `ExecStart=` relies on this.
        let cli = Cli::parse_from([
            "shellflow",
            "cred-env",
            "exec",
            "/usr/local/bin/zenohd",
            "-c",
            "/run/zenoh/zenoh.json5",
            "--listen",
            "tcp/0.0.0.0:7447",
        ]);
        match cli.command {
            Some(Command::CredEnv(cred_env)) => match cred_env.command {
                super::CredEnvCmd::Exec(e) => {
                    assert_eq!(
                        e.command,
                        vec![
                            "/usr/local/bin/zenohd".to_string(),
                            "-c".to_string(),
                            "/run/zenoh/zenoh.json5".to_string(),
                            "--listen".to_string(),
                            "tcp/0.0.0.0:7447".to_string(),
                        ]
                    );
                }
                other => panic!("expected exec subcommand, got {other:?}"),
            },
            other => panic!("expected cred-env subcommand, got {other:?}"),
        }
    }

    #[test]
    fn cred_env_exec_requires_a_command() {
        assert!(Cli::try_parse_from(["shellflow", "cred-env", "exec"]).is_err());
    }

    #[test]
    fn cred_env_render_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "cred-env",
            "render",
            "/etc/zenoh/zenoh.json5.tmpl",
            "/run/zenoh/zenoh.json5",
        ]);
        match cli.command {
            Some(Command::CredEnv(cred_env)) => match cred_env.command {
                super::CredEnvCmd::Render(r) => {
                    assert_eq!(r.template.to_string_lossy(), "/etc/zenoh/zenoh.json5.tmpl");
                    assert_eq!(r.output.to_string_lossy(), "/run/zenoh/zenoh.json5");
                }
                other => panic!("expected render subcommand, got {other:?}"),
            },
            other => panic!("expected cred-env subcommand, got {other:?}"),
        }
    }

    #[test]
    fn cred_env_credstore_install_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "cred-env",
            "credstore-install",
            "zenoh",
            "--store-dir",
            "/tmp/store/zenoh",
        ]);
        match cli.command {
            Some(Command::CredEnv(cred_env)) => match cred_env.command {
                super::CredEnvCmd::CredstoreInstall(c) => {
                    assert_eq!(c.service, "zenoh");
                    assert_eq!(
                        c.store_dir.map(|p| p.to_string_lossy().into_owned()),
                        Some("/tmp/store/zenoh".to_string())
                    );
                }
                other => panic!("expected credstore-install subcommand, got {other:?}"),
            },
            other => panic!("expected cred-env subcommand, got {other:?}"),
        }
    }

    #[test]
    fn secret_keys_check_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "secret",
            "keys-check",
            "-i",
            "/k.txt",
            "services/zenoh",
        ]);
        match cli.command {
            Some(Command::Secret(secret)) => match secret.command {
                super::SecretCmd::KeysCheck(c) => {
                    assert_eq!(c.dir.to_string_lossy(), "services/zenoh");
                    assert_eq!(
                        c.identity.map(|p| p.to_string_lossy().into_owned()),
                        Some("/k.txt".to_string())
                    );
                }
                other => panic!("expected keys-check subcommand, got {other:?}"),
            },
            other => panic!("expected secret subcommand, got {other:?}"),
        }
    }

    #[test]
    fn service_init_parses_hosts() {
        let cli = Cli::parse_from([
            "shellflow",
            "service",
            "init",
            "myapp",
            "--host",
            "api",
            "--host",
            "trade",
        ]);
        match cli.command {
            Some(Command::Service(service)) => match service.command {
                super::ServiceCmd::Init(i) => {
                    assert_eq!(i.service, "myapp");
                    assert_eq!(i.hosts, vec!["api".to_string(), "trade".to_string()]);
                }
                super::ServiceCmd::Check(_) |
                super::ServiceCmd::Diff(_) |
                super::ServiceCmd::Manifest(_) |
                super::ServiceCmd::Verify(_) |
                super::ServiceCmd::Status(_) => {
                    panic!("expected init subcommand")
                }
            },
            other => panic!("expected service subcommand, got {other:?}"),
        }
    }

    #[test]
    fn service_check_parses() {
        let cli = Cli::parse_from(["shellflow", "service", "check", "webhook", "--host", "api"]);
        match cli.command {
            Some(Command::Service(service)) => match service.command {
                super::ServiceCmd::Check(a) => {
                    assert_eq!(a.service.as_deref(), Some("webhook"));
                    assert_eq!(a.host, "api");
                    assert_eq!(a.journal_lines, 50);
                }
                super::ServiceCmd::Init(_) |
                super::ServiceCmd::Diff(_) |
                super::ServiceCmd::Manifest(_) |
                super::ServiceCmd::Verify(_) |
                super::ServiceCmd::Status(_) => {
                    panic!("expected check subcommand")
                }
            },
            other => panic!("expected service subcommand, got {other:?}"),
        }
    }

    #[test]
    fn service_init_pattern_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "service",
            "init",
            "myapp",
            "--pattern",
            "container",
            "--host",
            "api",
        ]);
        match cli.command {
            Some(Command::Service(service)) => match service.command {
                super::ServiceCmd::Init(i) => {
                    assert!(matches!(i.pattern, super::ServicePattern::Container));
                }
                super::ServiceCmd::Check(_) |
                super::ServiceCmd::Diff(_) |
                super::ServiceCmd::Manifest(_) |
                super::ServiceCmd::Verify(_) |
                super::ServiceCmd::Status(_) => {
                    panic!("expected init subcommand")
                }
            },
            other => panic!("expected service subcommand, got {other:?}"),
        }
    }

    #[test]
    fn emit_cred_env_parses() {
        let cli = Cli::parse_from(["shellflow", "emit", "cred-env", "-o", "/opt/cred-env"]);
        match cli.command {
            Some(Command::Emit(emit)) => match emit.command {
                super::EmitCmd::CredEnv(a) => {
                    assert_eq!(
                        a.output.map(|p| p.to_string_lossy().into_owned()),
                        Some("/opt/cred-env".to_string())
                    );
                }
            },
            other => panic!("expected emit subcommand, got {other:?}"),
        }
    }

    #[test]
    fn template_check_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "template",
            "check",
            "-i",
            "/keys.txt",
            "services/zenoh/zenoh.json5.tmpl",
            "services/zenoh/api.env.age",
        ]);
        match cli.command {
            Some(Command::Template(template)) => match template.command {
                super::TemplateCmd::Check(a) => {
                    assert_eq!(
                        a.identity.map(|p| p.to_string_lossy().into_owned()),
                        Some("/keys.txt".to_string())
                    );
                    assert_eq!(a.template.to_string_lossy(), "services/zenoh/zenoh.json5.tmpl");
                    assert_eq!(a.file.to_string_lossy(), "services/zenoh/api.env.age");
                }
                super::TemplateCmd::Render(_) => {
                    panic!("expected check subcommand")
                }
            },
            other => panic!("expected template subcommand, got {other:?}"),
        }
    }

    #[test]
    fn template_render_parses() {
        let cli = Cli::parse_from([
            "shellflow",
            "template",
            "render",
            "--format",
            "toml",
            "-i",
            "/keys.txt",
            "services/zenoh/zenoh.json5.tmpl",
            "services/zenoh/api.env.age",
        ]);
        match cli.command {
            Some(Command::Template(template)) => match template.command {
                super::TemplateCmd::Render(a) => {
                    assert!(matches!(a.format, super::RenderFormat::Toml));
                    assert_eq!(a.template.to_string_lossy(), "services/zenoh/zenoh.json5.tmpl");
                }
                super::TemplateCmd::Check(_) => {
                    panic!("expected render subcommand")
                }
            },
            other => panic!("expected template subcommand, got {other:?}"),
        }
    }

    /// The env var is process-global, so every test that mutates it takes
    /// this lock first.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_mask_env<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // SAFETY: serialized by ENV_LOCK; no other test reads this var
        // concurrently and the value is a non-secret test fixture.
        unsafe {
            match value {
                Some(v) => std::env::set_var(super::MASK_MIN_LEN_ENV, v),
                None => std::env::remove_var(super::MASK_MIN_LEN_ENV),
            }
        }
        let out = body();
        // SAFETY: serialized by ENV_LOCK, as above.
        unsafe {
            std::env::remove_var(super::MASK_MIN_LEN_ENV);
        }
        out
    }

    #[test]
    fn mask_min_len_defaults_to_six() {
        with_mask_env(None, || {
            assert_eq!(super::default_mask_min_len(), 6);
            let cli = Cli::parse_from(["shellflow", "deploy.sh"]);
            assert_eq!(cli.run.mask_min_len(), 6);
        });
    }

    #[test]
    fn mask_min_len_env_var_overrides_the_default() {
        with_mask_env(Some("3"), || {
            assert_eq!(super::default_mask_min_len(), 3);
            let cli = Cli::parse_from(["shellflow", "deploy.sh"]);
            assert_eq!(cli.run.mask_min_len(), 3);
        });
    }

    #[test]
    fn explicit_flag_beats_the_env_var() {
        with_mask_env(Some("3"), || {
            let cli = Cli::parse_from(["shellflow", "--mask-min-len", "12", "deploy.sh"]);
            assert_eq!(cli.run.mask_min_len(), 12);
        });
    }

    #[test]
    fn invalid_env_value_falls_back_to_the_default() {
        for bad in ["", "  ", "abc", "-1", "6.5"] {
            with_mask_env(Some(bad), || {
                assert_eq!(super::default_mask_min_len(), 6, "unexpected threshold for {bad:?}");
            });
        }
    }

    #[test]
    fn env_var_is_trimmed() {
        with_mask_env(Some(" 9\n"), || {
            assert_eq!(super::default_mask_min_len(), 9);
        });
    }
}
