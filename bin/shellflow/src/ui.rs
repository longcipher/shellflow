//! User-facing output helpers: step headers, host-prefixed streaming lines,
//! previews, and summaries. All output is routed through the [`Ui`] struct so
//! that `--log-file`, `--no-color`, and secret masking are applied uniformly.

use std::{
    io::{Write, stderr, stdout},
    path::PathBuf,
    sync::Arc,
};

use colored::Colorize;
use shellflow_core::{ExecutionPlan, Step, mask_line};

/// Verbosity levels, aligned with `-v`/`-vv`/`-vvv`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Verbosity(pub(crate) u8);

impl Verbosity {
    /// Show plan preview and per-step timing (`-v`).
    #[must_use]
    pub(crate) const fn info(self) -> bool {
        self.0 >= 1
    }

    /// Inject `set -x` tracing and `ssh -v` (`-vvv`).
    #[must_use]
    pub(crate) const fn trace(self) -> bool {
        self.0 >= 3
    }
}

/// Which stream produced a line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// A single buffered output line.
struct OutLine {
    host: String,
    stream: Stream,
    text: String,
}

/// Aggregated per-host result for a step summary.
#[derive(Clone, Debug)]
pub(crate) struct HostStatus {
    /// Host display alias.
    pub(crate) alias: String,
    /// Outcome for that host.
    pub(crate) outcome: Outcome,
}

/// Outcome of a host within a step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// Completed successfully.
    #[default]
    Ok,
    /// Skipped because `@only_if` failed.
    Skipped,
    /// The command exited non-zero.
    Failed,
    /// The step exceeded its timeout.
    TimedOut,
}

impl Outcome {
    fn colored(self) -> String {
        match self {
            Self::Ok => "OK".green(),
            Self::Skipped => "SKIPPED".dimmed(),
            Self::Failed => "FAILED".red(),
            Self::TimedOut => "TIMEOUT".yellow(),
        }
        .to_string()
    }
}

/// Output mode: stream immediately or buffer per host.
enum OutputModeState {
    /// Print every line as it arrives.
    Stream,
    /// Buffer each host's lines, flush when the host finishes.
    ///
    /// A `std::sync::Mutex` is used on purpose: every access happens behind
    /// the outer `Ui` mutex (so there is no real contention), and the
    /// `blocking_lock` below is safe because the flush critical section never
    /// awaits while holding the guard. This avoids the interleaving that a
    /// `try_lock`-failure fallback would produce.
    Grouped { buf: std::sync::Mutex<Vec<OutLine>> },
}

/// The output sink: aggregates host lines, applies masking, writes to stdout /
/// stderr and optionally an audit file.
pub(crate) struct Ui {
    verbose: Verbosity,
    secrets: Vec<String>,
    output: OutputModeState,
    /// Optional audit file, guarded by a plain `std::sync::Mutex`. The guard
    /// is never held across an await point, so blocking inside the async
    /// runtime is avoided (and `tokio::Mutex::blocking_lock` cannot panic).
    log_file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
}

impl Ui {
    /// Create a UI sink. `no_color` disables ANSI globally via colored.
    #[must_use]
    pub(crate) fn new(
        verbose: u8,
        no_color: bool,
        mode: super::cli::OutputMode,
        log_file: Option<PathBuf>,
    ) -> Self {
        colored::control::set_override(!no_color);
        let output = match mode {
            super::cli::OutputMode::Stream => OutputModeState::Stream,
            super::cli::OutputMode::Grouped => {
                OutputModeState::Grouped { buf: std::sync::Mutex::new(Vec::new()) }
            }
        };
        let log_file = log_file.and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|err| {
                    eprintln!("warning: cannot open log file {:?}: {err}", path.display());
                })
                .ok()
                .map(|file| Arc::new(std::sync::Mutex::new(file)))
        });
        Self { verbose: Verbosity(verbose), secrets: Vec::new(), output, log_file }
    }

    /// The verbosity level.
    #[must_use]
    pub(crate) const fn verbosity(&self) -> Verbosity {
        self.verbose
    }

    /// Register secret values to be masked in all output.
    pub(crate) fn set_secrets(&mut self, secrets: Vec<String>) {
        self.secrets = secrets;
    }

    /// Print a masked payload preview (used at `-vv`, dry-run, and diff).
    pub(crate) fn payload_preview(&self, title: &str, script: &str) {
        print_line(format!("  |--- {title} ---").dimmed().to_string());
        for line in script.lines() {
            print_line(format!("  | {}", self.mask(line)).dimmed().to_string());
        }
        print_line("  |------------------".dimmed().to_string());
    }

    /// Print the plan preview shown at `-v` and above.
    pub(crate) fn plan_preview(&self, plan: &ExecutionPlan) {
        if !self.verbose.info() {
            return;
        }
        print_line("Plan:".dimmed().to_string());
        for (name, spec) in &plan.servers {
            print_line(format!("  server  {name:>12} -> {spec:?}").dimmed().to_string());
        }
        for (name, members) in &plan.groups {
            print_line(
                format!("  group   {name:>12} -> {}", members.join(",")).dimmed().to_string(),
            );
        }
        for (idx, step) in plan.steps.iter().enumerate() {
            let target = step.target_text().map(|t| format!(" -> {t}")).unwrap_or_default();
            let name = step.name().map(|n| format!(" ({n})")).unwrap_or_default();
            print_line(
                format!("  step    {:>2}: {}{}{}", idx + 1, step.kind(), name, target)
                    .dimmed()
                    .to_string(),
            );
        }
    }

    /// Stream a line from a host; honors `--output grouped` by buffering.
    pub(crate) fn host_line(&self, host: &str, stream: Stream, line: &str) {
        let masked = self.mask(line);
        match &self.output {
            OutputModeState::Stream => self.emit_host_line(host, stream, &masked),
            OutputModeState::Grouped { buf } => {
                let mut buf = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                buf.push(OutLine { host: host.to_string(), stream, text: masked });
            }
        }
    }

    /// Flush grouped host buffers to stdout. No-op in stream mode.
    ///
    /// The critical section is drained without awaiting, so the blocking lock
    /// is safe even inside the async runtime.
    pub(crate) fn flush_grouped(&self) {
        if let OutputModeState::Grouped { buf } = &self.output {
            let lines = {
                let mut buf = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                std::mem::take(&mut *buf)
            };
            for line in lines {
                self.emit_host_line(&line.host, line.stream, &line.text);
            }
        }
    }

    fn emit_host_line(&self, host: &str, stream: Stream, text: &str) {
        let prefix = format!("[{host}]").blue().bold();
        let rendered = match stream {
            Stream::Stdout => format!("{prefix} {text}"),
            Stream::Stderr if self.verbose.trace() => {
                format!("{} {}", prefix.yellow(), text.yellow())
            }
            Stream::Stderr => format!("{} {}", prefix.red(), text.red()),
        };
        match stream {
            Stream::Stdout => {
                let mut out = stdout().lock();
                let _ = writeln!(out, "{rendered}");
            }
            Stream::Stderr => {
                let mut out = stderr().lock();
                let _ = writeln!(out, "{rendered}");
            }
        }
        if let Some(file) = &self.log_file {
            let marker = match stream {
                Stream::Stdout => "OUT",
                Stream::Stderr => "ERR",
            };
            let line = format!("[{host}] {marker} {text}\n");
            // Short critical section; the lock is released immediately.
            let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = file.write_all(line.as_bytes());
        }
    }

    fn mask(&self, line: &str) -> String {
        mask_line(line, &self.secrets)
    }
}

/// Write one line to stdout, flushing the lock immediately.
fn print_line(text: String) {
    let mut out = stdout().lock();
    let _ = writeln!(out, "{text}");
}

/// Print a step header.
pub(crate) fn step_header(index: usize, total: usize, step: &Step) {
    let kind_colored = match step.kind() {
        "local" => "local".green(),
        "remote" => "remote".yellow(),
        "copy" => "copy".cyan(),
        other => other.normal(),
    }
    .to_string();
    let target = step.target_text().map(|t| format!(" -> {t}")).unwrap_or_default();
    let name = step.name().map(|n| format!(" {n}")).unwrap_or_default();
    let label = format!("[STEP {index}/{total}]{name} {kind_colored}{target}").bold();
    print_line(format!("\n{label}"));
}

/// Print a note line (dimmed).
pub(crate) fn note(text: &str) {
    print_line(text.dimmed().to_string());
}

/// Print a warning line (yellow, prefixed with `!`).
pub(crate) fn warn(text: &str) {
    print_line(format!("  ! {text}").yellow().to_string());
}

/// Print a dry-run banner (magenta, bold).
pub(crate) fn dry_run_banner() {
    print_line(">>> [DRY RUN] no changes will be made <<<".magenta().bold().to_string());
}

/// Print the per-step host outcome line.
pub(crate) fn step_outcome(elapsed: std::time::Duration, statuses: &[HostStatus]) {
    let time = format!("{:.2}s", elapsed.as_secs_f64());
    let parts: Vec<String> =
        statuses.iter().map(|s| format!("{} {}", s.alias.cyan(), s.outcome.colored())).collect();
    print_line(format!("{} done in {time} ({})", "✔".bold(), parts.join(", ")));
}

/// Print the final run summary with per-step timing and host statuses.
pub(crate) fn final_summary(steps: &[(usize, std::time::Duration, Vec<HostStatus>)]) {
    print_line(String::new());
    print_line("Summary:".bold().to_string());
    for (idx, elapsed, statuses) in steps {
        let time = format!("{:.2}s", elapsed.as_secs_f64());
        let parts: Vec<String> = statuses
            .iter()
            .map(|s| format!("{} {}", s.alias.cyan(), s.outcome.colored()))
            .collect();
        print_line(format!(
            "  step {idx:>2}  {time:>8}  {}",
            if parts.is_empty() { "—".to_string() } else { parts.join(", ") }
        ));
    }
}

/// Print a failure note for a step in continue-on-error mode.
pub(crate) fn step_failed(index: usize, message: &str) {
    print_line(format!("Step {index} failed: {message}").red().to_string());
}
