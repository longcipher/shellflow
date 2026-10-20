//! Command-line interface definition (clap derive).
//!
//! `shellflow` is a multi-command CLI. The bare positional form
//! (`shellflow deploy.sh`) keeps working and is equivalent to
//! `shellflow run deploy.sh` — the `run` subcommand is the default.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

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
    #[arg(short = 'p', long, value_name = "N", default_value_t = 0)]
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

    /// Append every streamed line (tagged [host] + stream) to this file.
    #[arg(short = 'l', long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Disable ANSI colors.
    #[arg(long)]
    pub no_color: bool,

    /// Run remote blocks and copies on the local machine instead of over SSH
    /// (local debugging; no network or sudo required).
    #[arg(long)]
    pub local: bool,

    /// Age identity file for `@secrets` / `deploy` decryption.
    #[arg(short = 'i', long, value_name = "PATH")]
    pub identity: Option<PathBuf>,

    /// Reuse SSH connections within a run (`ControlMaster=auto`,
    /// `ControlPersist=60s`). Faster for many small steps; off by default
    /// so a stale master socket can never break a deploy silently.
    #[arg(long)]
    pub ssh_reuse: bool,

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
#[derive(Debug, Subcommand)]
pub(crate) enum ServiceCmd {
    /// Scaffold a new service in the flat layout (config template, systemd
    /// unit, deploy playbook skeleton) in the current repository.
    Init(ServiceInitArgs),
    /// Audit a deployed systemd unit over SSH (read-only): argv/env secret
    /// exposure, credential wiring, listening sockets, journal leak scan.
    Check(ServiceCheckArgs),
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
}

/// Arguments for `service init`.
#[derive(Debug, Args)]
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
#[derive(Debug, Args)]
pub(crate) struct ServiceCheckArgs {
    /// Service name (systemd unit `<svc>.service` on the target).
    #[arg(value_name = "SVC")]
    pub service: String,

    /// SSH target (alias, `[user@]host[:port]`, or `~/.ssh/config` entry).
    #[arg(long = "host", value_name = "HOST")]
    pub host: String,

    /// Also grep this many journal lines for secret-value shapes (default 50).
    #[arg(long, value_name = "N", default_value_t = 50)]
    pub journal_lines: usize,
}

/// The top-level CLI: a `run` subcommand (also the default via the bare
/// positional `SCRIPT`), plus `keys`, `secret`, `template`, and `emit`.
#[derive(Debug, Parser)]
#[command(name = "shellflow", version, about, long_about)]
#[command(args_conflicts_with_subcommands = true)]
pub(crate) struct Cli {
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
    /// Scaffold new services in the flat repository layout.
    Service(ServiceArgs),
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
                super::ServiceCmd::Check(_) => {
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
                    assert_eq!(a.service, "webhook");
                    assert_eq!(a.host, "api");
                    assert_eq!(a.journal_lines, 50);
                }
                super::ServiceCmd::Init(_) => {
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
                super::ServiceCmd::Check(_) => {
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
