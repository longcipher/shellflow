//! `shellflow` — ultra-fast, shell-native deployment tool.
//!
//! The binary owns the I/O boundary: it parses the CLI, runs preflight,
//! dispatches to subcommands (`run`/`keys`/`secret`), and drives the
//! execution engine. CLI crates may print to stdout/stderr for user-facing
//! streaming output (the workspace denies this by default for library code).

#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

mod cli;
mod cred_env;
mod emit;
mod executor;
mod keys;
mod preflight;
mod secret;
mod secrets;
mod service;
mod template;
mod ui;

use std::{sync::Arc, time::Duration};

use clap::Parser;
use eyre::{Context as _, Result};
use tokio::sync::Mutex;

use crate::{
    cli::{Cli, Command, RunArgs},
    executor::{RunOutcome, StepStats, execute_plan},
    preflight::{preflight_check, preflight_check_local},
    ui::HostStatus,
};

/// The exit code used when interrupted by a signal.
const EXIT_INTERRUPTED: i32 = 130;

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    let code = match &cli.command {
        None => run_or_deploy(&cli.run).await,
        Some(Command::Run(args)) => run_or_deploy(args).await,
        Some(Command::Keys(cmd)) => match keys::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
        Some(Command::Secret(cmd)) => match secret::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
        Some(Command::Template(cmd)) => {
            let ui = ui::Ui::new(0, false, cli::OutputMode::Stream, None);
            match template::run(&cmd.command, &ui) {
                Ok(()) => 0,
                Err(err) => {
                    eprintln!("error: {err:#}");
                    1
                }
            }
        }
        Some(Command::Emit(cmd)) => match emit::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
        Some(Command::CredEnv(cmd)) => match cred_env::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
        Some(Command::Service(cmd)) => match service::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
    };
    std::process::exit(code);
}

/// Run a deploy script (the default `run` path).
async fn run_or_deploy(run: &RunArgs) -> i32 {
    if let Err(msg) = run_preflight(run) {
        eprintln!("error: {msg}");
        return 3;
    }

    let content = match tokio::fs::read_to_string(&run.script)
        .await
        .wrap_err_with(|| format!("failed to read script `{}`", run.script.display()))
    {
        Ok(content) => content,
        Err(err) => {
            eprintln!("error: {err:#}");
            return 1;
        }
    };

    let plan = match shellflow_core::parse_script(&content) {
        Ok(plan) => plan,
        Err(err) => {
            eprintln!("error: {err}");
            return 1;
        }
    };

    run_plan(run, plan).await
}

/// Preflight for the `run` path; `--local` needs only `bash`.
fn run_preflight(run: &RunArgs) -> Result<(), String> {
    run_preflight_flags(&run.flags)
}

fn run_preflight_flags(flags: &cli::RunFlags) -> Result<(), String> {
    if flags.local { preflight_check_local() } else { preflight_check() }
}

/// Execute a plan and map the outcome to an exit code.
async fn run_plan(run: &RunArgs, plan: shellflow_core::ExecutionPlan) -> i32 {
    let total_steps = plan.steps.len();

    let progress: Arc<Mutex<Vec<StepStats>>> = Arc::new(Mutex::new(Vec::new()));

    let outcome = tokio::select! {
        outcome = execute_plan(run, plan, Arc::clone(&progress)) => outcome,
        _ = wait_for_signal() => {
            eprintln!("\ninterrupted — aborting; in-flight processes are being terminated");
            RunOutcome::Interrupted { total: total_steps }
        }
    };

    match outcome {
        RunOutcome::Success => 0,
        RunOutcome::Failed(executor::RunError::Config) => 1,
        RunOutcome::Failed(executor::RunError::Transport) => 3,
        RunOutcome::Failed(executor::RunError::Script) => 4,
        RunOutcome::Interrupted { total } => {
            eprintln!("interrupted — {total} total steps; in-flight processes were terminated");
            let done = progress.lock().await;
            if !done.is_empty() {
                let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
                    done.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
                crate::ui::final_summary(&summary, &None);
            }
            EXIT_INTERRUPTED
        }
    }
}

/// Initialize `tracing_subscriber` with an env-filter defaulting to `info`.
fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ =
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}

/// Resolve when SIGINT or SIGTERM is received.
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
