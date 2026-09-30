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
    /// Print the `ImportCredential=KEY` lines for an env file.
    Creds(SecretCredsArgs),
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
    /// `--recipients-dir` is given.
    #[arg(short = 'r', long = "recipient", value_name = "AGE1...")]
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

    /// The encrypted env file to read.
    #[arg(value_name = "FILE")]
    pub file: PathBuf,
}

/// The top-level CLI: a `run` subcommand (also the default via the bare
/// positional `SCRIPT`), plus `keys` and `secret`.
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
}

impl RunArgs {
    /// The parsed `--target` restriction list.
    #[must_use]
    pub(crate) fn target_restrict(&self) -> Vec<String> {
        self.flags
            .target
            .as_deref()
            .map(|t| {
                t.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default()
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
                other => panic!("expected generate subcommand, got {other:?}"),
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
