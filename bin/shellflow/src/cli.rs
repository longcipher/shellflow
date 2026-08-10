//! Command-line interface definition (clap derive).

use std::path::PathBuf;

use clap::{ArgAction, Parser};

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

/// Ultra-fast, shell-native deployment tool.
///
/// `shellflow` turns a plain Bash script annotated with `# @` comment
/// directives into a concurrent local/remote deployment run. The script stays
/// 100% valid Bash — `bash deploy.sh` works unchanged.
#[derive(Debug, Parser)]
#[command(name = "shellflow", version, about, long_about)]
pub(crate) struct Cli {
    /// Deploy script path.
    #[arg(value_name = "SCRIPT", default_value = "deploy.sh")]
    pub script: PathBuf,

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
}

impl Cli {
    /// The parsed `--target` restriction list.
    #[must_use]
    pub(crate) fn target_restrict(&self) -> Vec<String> {
        self.target
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
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn parses_default_script() {
        let cli = Cli::parse_from(["shellflow"]);
        assert_eq!(cli.script.to_string_lossy(), "deploy.sh");
    }

    #[test]
    fn parses_verbose_counts() {
        let cli = Cli::parse_from(["shellflow", "-vvv"]);
        assert_eq!(cli.verbose, 3);
    }

    #[test]
    fn parses_target_restrict() {
        let cli = Cli::parse_from(["shellflow", "-t", "web1, web2"]);
        assert_eq!(cli.target_restrict(), vec!["web1", "web2"]);
    }

    #[test]
    fn empty_target_restrict() {
        let cli = Cli::parse_from(["shellflow"]);
        assert_eq!(cli.target_restrict(), Vec::<String>::new());
    }
}
