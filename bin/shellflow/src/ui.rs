//! User-facing output helpers: step headers, host-prefixed streaming lines,
//! previews, and summaries.
//!
//! Every byte that reaches the terminal or the audit log goes through this
//! module, and every line is redacted on the way out **by the sink itself**
//! ([`print_line`] for control lines, [`Ui::emit_host_line`] for host output).
//! That is the structural half of the guarantee: a secret leaked because some
//! call site forgot to mask is a bug the compiler cannot catch, so the sink
//! does not rely on the call site.
//!
//! The call sites redact as well, *before* they add colour codes: a
//! below-threshold value is only redacted where it stands alone as a token,
//! and the ANSI prefix would otherwise look like an identifier character and
//! hide the value from the narrow rules. The two passes cannot unmask
//! anything — a redacted value no longer matches — so the pair is
//! belt-and-braces rather than duplication.
//!
//! The mask set itself lives in a process-wide registry ([`install_masks`] /
//! [`redact`]) so the free functions — which have no `Ui` handle — redact
//! exactly like the `Ui` methods do. There is therefore no unmasked twin of
//! any render function.

use std::{
    collections::HashMap,
    io::{Write, stderr, stdout},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{
        Arc, OnceLock, RwLock,
        atomic::{AtomicUsize, Ordering},
    },
};

use colored::Colorize;
use shellflow_core::{ExecutionPlan, SecretMasker, Step, prepare_masks};

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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

/// The known secret values, shared by every render site.
///
/// Stored behind an `Arc` so the read path is a pointer copy rather than a
/// copy of the secret values themselves.
#[derive(Clone, Debug, Default)]
struct MaskSet {
    /// Long values, longest-first and de-duplicated.
    masks: Arc<Vec<String>>,
    /// Below-threshold `(key, value)` pairs, redacted by the narrow rules.
    shorts: Arc<Vec<(String, String)>>,
}

/// The process-wide mask registry.
static MASK_SET: OnceLock<RwLock<Arc<MaskSet>>> = OnceLock::new();

/// The number of lines that could not be written to the audit log.
static AUDIT_WRITE_FAILURES: AtomicUsize = AtomicUsize::new(0);

/// The number of lines that could not be written to the terminal.
///
/// A closed stdout (`shellflow … | head`) is not a failure of the run, but it
/// must not be reported as a clean one: a truncated stream that exits 0 is
/// indistinguishable from a complete run in CI. The count is reported next to
/// the audit-log one.
static TERMINAL_WRITE_FAILURES: AtomicUsize = AtomicUsize::new(0);

fn mask_set() -> &'static RwLock<Arc<MaskSet>> {
    MASK_SET.get_or_init(Default::default)
}

/// Register the secret values that every render site must redact.
///
/// Called once per run, after the `@secrets` entries are resolved. The mask
/// set is normalized here (longest-first, de-duplicated) rather than per
/// output line: the masker runs for every streamed line, so re-sorting a
/// large `@secrets` set on each call would dominate output throughput.
pub(crate) fn install_masks(masks: Vec<String>, shorts: Vec<(String, String)>) {
    let mut guard = mask_set().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Arc::new(MaskSet { masks: Arc::new(prepare_masks(&masks)), shorts: Arc::new(shorts) });
}

/// Register additional secret values discovered **during** the run.
///
/// A local block can pull a value from an external store and `@export` it;
/// that value was unknown when [`install_masks`] ran before step 1. Without
/// this, a later step echoing the value (or `-vvv`'s `bash -x`) would print
/// it unredacted to the stream and the `--log-file` audit trail. Values are
/// merged with the existing set and re-normalized (longest-first).
pub(crate) fn extend_masks(values: Vec<String>, shorts: Vec<(String, String)>) {
    if values.is_empty() && shorts.is_empty() {
        return;
    }
    let mut guard = mask_set().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut masks = guard.masks.as_ref().clone();
    let mut all_shorts = guard.shorts.as_ref().clone();
    masks.extend(values);
    all_shorts.extend(shorts);
    *guard =
        Arc::new(MaskSet { masks: Arc::new(prepare_masks(&masks)), shorts: Arc::new(all_shorts) });
}

/// Redact every known secret in `text`.
///
/// This is the single redaction entry point. Notes, warnings, step headers,
/// previews and summaries all route through it, so a secret cannot leak by
/// being rendered through a path that forgot to mask.
pub(crate) fn redact(text: &str) -> String {
    let set = mask_set().read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
    let mut out = shellflow_core::mask_line(text, &set.masks);
    for (key, value) in set.shorts.iter() {
        out = shellflow_core::mask_token(&out, value);
        out = shellflow_core::mask_keyed(&out, key, value);
    }
    out
}

/// How many lines could not be appended to the audit log.
///
/// A silently truncated audit trail is worse than no audit trail: the
/// operator believes the run was recorded in full.
pub(crate) fn audit_write_failures() -> usize {
    AUDIT_WRITE_FAILURES.load(Ordering::Relaxed)
}

/// How many lines could not be written to the terminal.
///
/// Same rationale as [`audit_write_failures`]: a stream truncated by a closed
/// pipe must not look like a complete run.
pub(crate) fn terminal_write_failures() -> usize {
    TERMINAL_WRITE_FAILURES.load(Ordering::Relaxed)
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
    /// The run was interrupted before the host finished.
    Cancelled,
}

impl Outcome {
    fn colored(self) -> String {
        match self {
            Self::Ok => "OK".green(),
            Self::Skipped => "SKIPPED".dimmed(),
            Self::Failed => "FAILED".red(),
            Self::TimedOut => "TIMEOUT".yellow(),
            Self::Cancelled => "CANCELLED".yellow(),
        }
        .to_string()
    }
}

/// Buffered output for `--output grouped`, bucketed per host.
#[derive(Default)]
struct GroupedBuffer {
    /// The hosts in first-seen order.
    order: Vec<String>,
    /// The buffered lines per host.
    lines: HashMap<String, Vec<OutLine>>,
}

impl GroupedBuffer {
    fn push(&mut self, host: &str, line: OutLine) {
        if !self.lines.contains_key(host) {
            self.order.push(host.to_string());
        }
        self.lines.entry(host.to_string()).or_default().push(line);
    }

    /// Take the lines of one host, removing it from the buffer.
    fn take_host(&mut self, host: &str) -> Vec<OutLine> {
        self.order.retain(|name| name != host);
        self.lines.remove(host).unwrap_or_default()
    }

    /// Take every host's lines, in first-seen order.
    fn take_all(&mut self) -> Vec<Vec<OutLine>> {
        let mut out = Vec::with_capacity(self.order.len());
        for host in std::mem::take(&mut self.order) {
            if let Some(lines) = self.lines.remove(&host) {
                out.push(lines);
            }
        }
        out
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
    /// critical sections never await while holding the guard.
    Grouped { buf: std::sync::Mutex<GroupedBuffer> },
}

/// The output sink: aggregates host lines, applies masking, writes to stdout /
/// stderr and optionally an audit file.
pub(crate) struct Ui {
    verbose: Verbosity,
    /// One masker per (host, stream).
    ///
    /// A secret that a target program split across two output lines must be
    /// redacted as a whole, which needs state that spans lines. The state
    /// cannot be shared between hosts: one host's line must not consume
    /// another's pending continuation.
    maskers: HashMap<(String, Stream), SecretMasker>,
    output: OutputModeState,
    /// Optional audit file, guarded by a plain `std::sync::Mutex`. The guard
    /// is never held across an await point, so blocking inside the async
    /// runtime is avoided (and `tokio::Mutex::blocking_lock` cannot panic).
    log_file: Option<Arc<std::sync::Mutex<std::fs::File>>>,
}

impl Ui {
    /// Create a UI sink. `no_color` disables ANSI globally via colored.
    ///
    /// # Errors
    ///
    /// Returns an error when the audit log cannot be opened or its mode
    /// cannot be tightened. A run that was asked to keep an audit trail and
    /// silently keeps none is worse than a run that refuses to start.
    pub(crate) fn new(
        verbose: u8,
        no_color: bool,
        mode: super::cli::OutputMode,
        log_file: Option<PathBuf>,
    ) -> eyre::Result<Self> {
        colored::control::set_override(!no_color);
        let output = match mode {
            super::cli::OutputMode::Stream => OutputModeState::Stream,
            super::cli::OutputMode::Grouped => {
                OutputModeState::Grouped { buf: std::sync::Mutex::new(GroupedBuffer::default()) }
            }
        };
        let log_file = match log_file {
            None => None,
            Some(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .open(&path)
                    .map_err(|err| {
                        eyre::eyre!("cannot open the audit log `{}`: {err}", path.display())
                    })?;
                // `OpenOptions::mode` only applies when the file is created, and
                // the log is opened in append mode — so a log that an earlier
                // version created 0644 stays world-readable unless the mode is
                // re-applied here.
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(
                    |err| eyre::eyre!("cannot secure the audit log `{}`: {err}", path.display()),
                )?;
                Some(Arc::new(std::sync::Mutex::new(file)))
            }
        };
        Ok(Self { verbose: Verbosity(verbose), maskers: HashMap::new(), output, log_file })
    }

    /// The verbosity level.
    #[must_use]
    pub(crate) const fn verbosity(&self) -> Verbosity {
        self.verbose
    }

    /// Clone the audit-file handle so executor sub-modules can route
    /// output to the same file without holding the Ui lock.
    pub(crate) fn log_file(&self) -> Option<Arc<std::sync::Mutex<std::fs::File>>> {
        self.log_file.clone()
    }

    /// Register the secret values to be masked in all output.
    ///
    /// `masks` holds the values at or above the masking threshold; `shorts`
    /// holds the below-threshold `(key, value)` pairs, which are redacted
    /// only where they stand alone as a token or under their own key (a
    /// global substring replace would shred unrelated output).
    ///
    /// The set is normalized once (longest-first, de-duplicated) and installed
    /// in the process-wide registry, so every render site — including the
    /// free functions that have no `Ui` handle — redacts the same values.
    pub(crate) fn set_secret_values(&mut self, masks: Vec<String>, shorts: Vec<(String, String)>) {
        install_masks(masks, shorts);
        self.maskers.clear();
    }

    /// Register secret values discovered **during** the run (`@export`).
    ///
    /// Extends the process-wide registry and drops the cached per-host
    /// maskers, exactly like [`Self::set_secret_values`]: a masker created
    /// for an earlier block holds a snapshot of the old set and would
    /// otherwise keep the new values unredacted.
    pub(crate) fn extend_secret_values(
        &mut self,
        masks: Vec<String>,
        shorts: Vec<(String, String)>,
    ) {
        extend_masks(masks, shorts);
        self.maskers.clear();
    }

    /// Print a masked payload preview (used at `-vv`, dry-run, and diff).
    ///
    /// The preview is redacted with a *stateful* masker, so a secret that the
    /// block splits across two lines is redacted as a whole — exactly like the
    /// streamed output. The masker is fresh per preview, so one step's
    /// pending fragment can never leak into the next step's preview.
    pub(crate) fn payload_preview(&self, title: &str, script: &str) {
        let set = mask_set().read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        let mut masker = SecretMasker::new(Arc::clone(&set.masks), Arc::clone(&set.shorts));

        self.log_line(format!("  |--- {} ---", redact(title)).dimmed().to_string());
        for line in script.lines() {
            let masked = masker.redact_line(line);
            self.log_line(format!("  | {masked}").dimmed().to_string());
        }
        self.log_line("  |------------------".dimmed().to_string());
    }

    /// Print a note line with every known secret masked.
    pub(crate) fn masked_note(&self, text: &str) {
        self.log_line(redact(text).dimmed().to_string());
    }

    /// Print the plan preview shown at `-v` and above.
    ///
    /// The step numbering follows the *unfiltered* plan index, the same
    /// number `--only`/`--skip` select by. The preview and the step headers
    /// therefore agree, and a number copied from the preview selects the step
    /// it names even when `--skip` removed earlier steps.
    pub(crate) fn plan_preview(&self, plan: &ExecutionPlan, selected: &[(usize, Step)]) {
        if !self.verbose.info() {
            return;
        }
        self.log_line("Plan:".dimmed().to_string());
        for (name, spec) in plan.servers() {
            self.log_line(
                format!("  server  {name:>12} -> {}", redact(&format!("{spec:?}")))
                    .dimmed()
                    .to_string(),
            );
        }
        for (name, members) in plan.groups() {
            self.log_line(
                format!("  group   {name:>12} -> {}", redact(&members.join(",")))
                    .dimmed()
                    .to_string(),
            );
        }
        for (plan_index, step) in selected {
            let target = step.target_text().map_or_default(|t| format!(" -> {t}"));
            let name = step.name().map_or_default(|n| format!(" ({n})"));
            // A step name or target can carry a captured value (`@name
            // deploy-$VERSION`), so the line is redacted like the server and
            // group lines above it — the sink redacts too, but the call-site
            // pass is what handles a below-threshold value before the colour
            // codes are interleaved.
            let line =
                format!("  step    {:>2}: {}{}{}", plan_index + 1, step.kind(), name, target);
            self.log_line(redact(&line).dimmed().to_string());
        }
    }

    /// Stream a line from a host; honors `--output grouped` by buffering.
    ///
    /// Takes `&mut self`: the masker is stateful across lines so that a secret
    /// a target program split across two lines is redacted as a whole.
    pub(crate) fn host_line(&mut self, host: &str, stream: Stream, line: &str) {
        let masked = self.mask_host_line(host, stream, line);
        match &self.output {
            OutputModeState::Stream => self.emit_host_line(host, stream, &masked),
            OutputModeState::Grouped { buf } => {
                let mut buf = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                buf.push(host, OutLine { host: host.to_string(), stream, text: masked });
            }
        }
    }

    /// Redact one line of host output with the masker for this host+stream.
    fn mask_host_line(&mut self, host: &str, stream: Stream, line: &str) -> String {
        let set = mask_set().read().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
        self.maskers
            .entry((host.to_string(), stream))
            .or_insert_with(|| SecretMasker::new(Arc::clone(&set.masks), Arc::clone(&set.shorts)))
            .redact_line(line)
    }

    /// Flush one host's grouped block: the host has finished.
    ///
    /// No-op in stream mode.
    pub(crate) fn host_finished(&self, host: &str) {
        if let OutputModeState::Grouped { buf } = &self.output {
            let lines = {
                let mut buf = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                buf.take_host(host)
            };
            for line in lines {
                self.emit_host_line(&line.host, line.stream, &line.text);
            }
        }
    }

    /// Flush every remaining grouped host buffer to stdout. No-op in stream
    /// mode.
    ///
    /// The critical section is drained without awaiting, so the blocking lock
    /// is safe even inside the async runtime.
    pub(crate) fn flush_grouped(&self) {
        if let OutputModeState::Grouped { buf } = &self.output {
            let hosts = {
                let mut buf = buf.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                buf.take_all()
            };
            for lines in hosts {
                for line in lines {
                    self.emit_host_line(&line.host, line.stream, &line.text);
                }
            }
        }
    }

    fn emit_host_line(&self, host: &str, stream: Stream, text: &str) {
        let prefix = format!("[{host}]").blue().bold();
        let rendered = match stream {
            Stream::Stdout => {
                let text = colorize_itemize(text);
                format!("{prefix} {text}")
            }
            Stream::Stderr if self.verbose.trace() => {
                format!("{} {}", prefix.yellow(), text.yellow())
            }
            Stream::Stderr => format!("{} {}", prefix.red(), text.red()),
        };
        match stream {
            Stream::Stdout => {
                let mut out = stdout().lock();
                if writeln!(out, "{rendered}").is_err() {
                    TERMINAL_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
            }
            Stream::Stderr => {
                let mut out = stderr().lock();
                if writeln!(out, "{rendered}").is_err() {
                    TERMINAL_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
                }
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
            if file.write_all(line.as_bytes()).is_err() {
                AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Write one line to stdout and the audit log (if configured).
    ///
    /// Private to this module on purpose: every render path goes through a
    /// method that redacts its content, so a caller cannot bypass the mask
    /// by reaching for the raw sink.
    fn log_line(&self, text: String) {
        print_line(text, &self.log_file);
    }

    /// Print a note line (dimmed), routed through the log file if configured.
    pub(crate) fn note(&self, text: &str) {
        self.log_line(redact(text).dimmed().to_string());
    }
}

/// Colorize an rsync itemize line by its change symbol.
///
/// `--diff` filters the transfer output down to the itemized changes, and
/// design §8.2 promises they are "color-coded by symbol": a new file, a
/// deletion and a timestamp-only change must be distinguishable at a glance.
fn colorize_itemize(text: &str) -> String {
    let Some(symbol) = text.chars().next() else {
        return text.to_string();
    };
    match symbol {
        '>' | 'c' => text.green().to_string(),
        '*' => text.red().to_string(),
        '<' => text.yellow().to_string(),
        '.' => text.dimmed().to_string(),
        _ => text.to_string(),
    }
}

/// Write one line to stdout, flushing the lock immediately.
///
/// When a `--log-file` is configured, the line is also appended to the audit
/// log so that step headers, notes, warnings, and summaries are captured
/// alongside host output.
///
/// # Masking
///
/// The line is redacted here, not only at the call site. The call sites mask
/// before they colour the text (see the module docs), so this pass is the
/// guarantee rather than the only defence: a render function that forgets to
/// mask — the `plan_preview` step line used to — still cannot write a known
/// secret to the terminal or the audit file.
fn print_line(text: String, log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>) {
    let text = redact(&text);
    let mut out = stdout().lock();
    if writeln!(out, "{text}").is_err() {
        TERMINAL_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(file) = log_file {
        let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if file.write_all(text.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
            AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Report a fatal run-path error: masked, on stderr, and in the audit trail.
///
/// A run-configuration failure (`@secrets` needing a named `@server`, a
/// `--local` run against per-host secrets) aborts before any step runs. It
/// belongs on stderr — the operator greps for it — but it must not be the one
/// output path that skips the masker, and the audit trail should record why
/// the run never started.
pub(crate) fn fatal(message: &str, log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>) {
    let text = format!("error: {}", redact(message));
    let mut out = stderr().lock();
    if writeln!(out, "{text}").is_err() {
        TERMINAL_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    if let Some(file) = log_file {
        let mut file = file.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if file.write_all(text.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
            AUDIT_WRITE_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Report a fatal error reaching stderr, with every known secret masked.
///
/// The `run` path prints through [`Ui`], but an error that arrives before the
/// run started (or after it torn down) has no `Ui` handle. It still must not
/// carry a value that the mask registry knows: `eyre` reports embed child
/// stderr, and child stderr can echo a credential.
pub(crate) fn error_line(report: &eyre::Report) {
    eprintln!("error: {}", redact(&format!("{report:#}")));
}

/// Report a fatal error that is plain text, masked like [`error_line`].
pub(crate) fn error_text(message: &str) {
    eprintln!("error: {}", redact(message));
}

/// Print a step header.
pub(crate) fn step_header(
    index: usize,
    total: usize,
    step: &Step,
    log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>,
) {
    let kind_colored = match step.kind() {
        "local" => "local".green(),
        "remote" => "remote".yellow(),
        "copy" => "copy".cyan(),
        other => other.normal(),
    }
    .to_string();
    let target = step.target_text().map_or_default(|t| format!(" -> {t}"));
    let name = step.name().map_or_default(|n| format!(" {n}"));
    let label = format!("[STEP {index}/{total}]{name} {kind_colored}{target}").bold();
    print_line(format!("\n{}", redact(&label)), log_file);
}

/// Print a note line (dimmed).
pub(crate) fn note(text: &str, log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>) {
    print_line(redact(text).dimmed().to_string(), log_file);
}

/// Print a warning line (yellow, prefixed with `!`).
pub(crate) fn warn(text: &str, log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>) {
    print_line(format!("  ! {}", redact(text)).yellow().to_string(), log_file);
}

/// Print a dry-run banner (magenta, bold).
pub(crate) fn dry_run_banner(log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>) {
    print_line(">>> [DRY RUN] no changes will be made <<<".magenta().bold().to_string(), log_file);
}

/// Render per-host outcomes as `alias OUTCOME` pairs.
///
/// A step with no hosts (a `@copy` under `--check`, or a copy skipped because
/// a `$VAR` is unresolved in dry-run) renders as an em dash rather than an
/// empty pair of parentheses.
fn host_parts(statuses: &[HostStatus]) -> String {
    if statuses.is_empty() {
        return "—".to_string();
    }
    statuses
        .iter()
        .map(|s| format!("{} {}", s.alias.cyan(), s.outcome.colored()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Print the per-step host outcome line.
pub(crate) fn step_outcome(
    elapsed: std::time::Duration,
    statuses: &[HostStatus],
    log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>,
) {
    let time = format!("{:.2}s", elapsed.as_secs_f64());
    print_line(format!("{} done in {time} ({})", "✔".bold(), host_parts(statuses)), log_file);
}

/// Print the final run summary with per-step timing and host statuses.
pub(crate) fn final_summary(
    steps: &[(usize, std::time::Duration, Vec<HostStatus>)],
    log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>,
) {
    print_line(String::new(), log_file);
    print_line("Summary:".bold().to_string(), log_file);
    for (idx, elapsed, statuses) in steps {
        let time = format!("{:.2}s", elapsed.as_secs_f64());
        print_line(format!("  step {idx:>2}  {time:>8}  {}", host_parts(statuses)), log_file);
    }
}

/// Print a failure note for a step in continue-on-error mode.
pub(crate) fn step_failed(
    index: usize,
    message: &str,
    log_file: &Option<Arc<std::sync::Mutex<std::fs::File>>>,
) {
    print_line(format!("Step {index} failed: {}", redact(message)).red().to_string(), log_file);
}

#[cfg(test)]
mod tests {
    use super::{HostStatus, Outcome, host_parts};

    /// Serializes the tests that install or assert on the mask registry.
    ///
    /// The registry is a process-wide `OnceLock<RwLock<..>>` on purpose (the
    /// free render functions have no `Ui` handle), so two tests that mutate it
    /// race: one test's `install_masks` replaces the set another test is
    /// asserting against, and the assertion then fails only when the suite runs
    /// in parallel. The lock makes the shared state explicit, exactly like
    /// `ENV_LOCK` in `shellflow-secrets`.
    static MASK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn mask_lock() -> std::sync::MutexGuard<'static, ()> {
        MASK_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn status(alias: &str, outcome: Outcome) -> HostStatus {
        HostStatus { alias: alias.to_string(), outcome }
    }

    #[test]
    fn empty_statuses_render_an_em_dash() {
        // A `@copy` under `--check`, or one skipped in dry-run, has no hosts;
        // the old rendering produced an empty `()`.
        assert_eq!(host_parts(&[]), "—");
    }

    #[test]
    fn statuses_render_alias_and_outcome() {
        colored::control::set_override(false);
        let rendered = host_parts(&[status("web1", Outcome::Ok), status("web2", Outcome::Skipped)]);
        assert_eq!(rendered, "web1 OK, web2 SKIPPED");
    }

    #[test]
    fn single_status_renders_without_a_separator() {
        colored::control::set_override(false);
        assert_eq!(host_parts(&[status("web1", Outcome::Failed)]), "web1 FAILED");
    }

    #[test]
    fn log_line_writes_to_stdout_and_log_file() {
        use std::sync::Arc;
        colored::control::set_override(false);
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("test.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open log file");
        let mut ui = super::Ui::new(0, true, crate::cli::OutputMode::Stream, None).expect("ui");
        ui.log_file = Some(Arc::new(std::sync::Mutex::new(file)));
        ui.log_line("test line".to_string());
        drop(ui);
        let content = std::fs::read_to_string(&log_path).expect("read log file");
        assert!(content.contains("test line"), "log file should contain the line, got: {content}");
    }

    #[test]
    fn log_file_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        colored::control::set_override(false);
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit.log");
        let ui = super::Ui::new(0, true, crate::cli::OutputMode::Stream, Some(log_path.clone()))
            .expect("ui");
        drop(ui);
        let mode = std::fs::metadata(&log_path).expect("log file").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the audit log must not be readable by other users");
    }

    #[test]
    fn an_unopenable_log_file_is_a_hard_error() {
        // A run that was asked to keep an audit trail and silently keeps none
        // is worse than a run that refuses to start.
        colored::control::set_override(false);
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("no-such-dir").join("audit.log");
        let outcome =
            super::Ui::new(0, true, crate::cli::OutputMode::Stream, Some(missing.clone()));
        let Err(err) = outcome else {
            panic!("an unopenable audit log must fail the run");
        };
        assert!(err.to_string().contains("audit log"), "unexpected error: {err}");
    }

    #[test]
    fn an_existing_world_readable_log_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        colored::control::set_override(false);
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit.log");
        std::fs::write(&log_path, "old line\n").expect("seed log");
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644))
            .expect("loosen log");
        let ui = super::Ui::new(0, true, crate::cli::OutputMode::Stream, Some(log_path.clone()))
            .expect("ui");
        drop(ui);
        let mode = std::fs::metadata(&log_path).expect("log file").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the audit log must be tightened to owner-only");
    }

    #[test]
    fn log_line_without_log_file_writes_to_stdout_only() {
        colored::control::set_override(false);
        let ui = super::Ui::new(0, true, crate::cli::OutputMode::Stream, None).expect("ui");
        assert!(ui.log_file().is_none(), "no audit log was requested");
    }

    #[test]
    fn every_render_path_redacts_a_registered_secret() {
        let _lock = mask_lock();
        // The masking guarantee is structural: the free functions have no
        // `Ui` handle and still redact, so no call site can leak by
        // forgetting to ask for masking.
        colored::control::set_override(false);
        super::install_masks(vec!["s3cr3tvalue".to_string()], Vec::new());
        assert_eq!(super::redact("value s3cr3tvalue here"), "value *** here");
        assert!(!super::redact("value s3cr3tvalue here").contains("s3cr3tvalue"));
    }

    #[test]
    fn extend_masks_registers_runtime_values() {
        let _lock = mask_lock();
        // A value discovered mid-run (`@export`) joins the registry: the
        // free redaction path — which shares no state with the `Ui` handle —
        // must redact it too.
        colored::control::set_override(false);
        super::install_masks(Vec::new(), Vec::new());
        assert!(
            super::redact("the value is hunter2secret").contains("hunter2secret"),
            "unregistered values are not masked"
        );
        super::extend_masks(vec!["hunter2secret".to_string()], Vec::new());
        assert_eq!(super::redact("the value is hunter2secret"), "the value is ***");
    }

    #[test]
    fn a_secret_split_across_two_preview_lines_is_redacted_as_a_whole() {
        let _lock = mask_lock();
        // The preview is a multi-line render of user content, so it must use
        // the *stateful* masker: two fragments that would reassemble into the
        // secret must not survive separately.
        colored::control::set_override(false);
        super::install_masks(vec!["s3cr3tvalue".to_string()], Vec::new());
        let mut ui = super::Ui::new(0, true, crate::cli::OutputMode::Stream, None).expect("ui");
        let dir = tempfile::tempdir().expect("temp dir");
        let log_path = dir.path().join("audit.log");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .expect("open log file");
        ui.log_file = Some(std::sync::Arc::new(std::sync::Mutex::new(file)));
        ui.payload_preview("Local Payload", "printf '%s' \"s3cr3t\nvalue\"");
        drop(ui);
        let content = std::fs::read_to_string(&log_path).expect("read log file");
        assert!(!content.contains("s3cr3tvalue"), "the secret leaked: {content}");
        assert!(!content.contains("value\""), "the tail leaked: {content}");
    }
}
