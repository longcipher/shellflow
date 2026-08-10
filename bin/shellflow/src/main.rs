//! `shellflow` — ultra-fast, shell-native deployment tool.
//!
//! The binary owns the I/O boundary: it reads the deploy script, runs the
//! parser, checks that system tools exist, and drives the execution engine.
//! CLI crates may print to stdout/stderr for user-facing streaming output
//! (the workspace denies this by default for library code).

#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

mod cli;
mod executor;
mod preflight;
mod ui;

use std::{sync::Arc, time::Duration};

use clap::Parser;
use eyre::{Context, Result};
use tokio::sync::Mutex;

use crate::{
    cli::Cli,
    executor::{RunError, RunOutcome, StepStats, execute_plan},
    preflight::preflight_check,
    ui::HostStatus,
};

/// The exit code used when interrupted by a signal.
const EXIT_INTERRUPTED: i32 = 130;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    if let Err(msg) = preflight_check() {
        eprintln!("error: {msg}");
        std::process::exit(3);
    }

    let content = tokio::fs::read_to_string(&cli.script)
        .await
        .wrap_err_with(|| format!("failed to read script `{}`", cli.script.display()))?;

    let plan = match shellflow_core::parse_script(&content) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(1);
        }
    };

    // Total step count for the interrupt summary.
    let total_steps = plan.steps.len();

    // Completed-step statistics shared with the executor so an interrupt can
    // still report what finished before the signal.
    let progress: Arc<Mutex<Vec<StepStats>>> = Arc::new(Mutex::new(Vec::new()));

    // Run the plan; on SIGINT/SIGTERM abort it (kill_on_drop reaps children)
    // and exit 130.
    let outcome = tokio::select! {
        outcome = execute_plan(&cli, plan, Arc::clone(&progress)) => outcome,
        _ = wait_for_signal() => {
            eprintln!("\ninterrupted — aborting; in-flight processes are being terminated");
            RunOutcome::Interrupted { total: total_steps }
        }
    };

    let code = match outcome {
        RunOutcome::Success => 0,
        RunOutcome::Failed(RunError::Transport) => 3,
        RunOutcome::Failed(RunError::Script) => 4,
        RunOutcome::Interrupted { total } => {
            eprintln!("interrupted — {total} total steps; in-flight processes were terminated");
            // Report what completed before the interrupt (design §7.5).
            let done = progress.lock().await;
            if !done.is_empty() {
                let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
                    done.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
                crate::ui::final_summary(&summary);
            }
            EXIT_INTERRUPTED
        }
    };
    std::process::exit(code);
}

/// Initialize `tracing_subscriber` with an env-filter defaulting to `info`.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

/// Resolve when SIGINT or SIGTERM is received.
///
/// Returns `io::Result<()>` (not a bare `()`) so callers can bind the future
/// with a `_` pattern without triggering `ignored_unit_patterns`.
async fn wait_for_signal() -> std::io::Result<()> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        signal = term.recv() => {
            let _ = signal;
            Ok(())
        }
    }
}
