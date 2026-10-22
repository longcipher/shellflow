//! `shellflow` — ultra-fast, shell-native deployment tool.
//!
//! The binary owns the I/O boundary: it parses the CLI, runs preflight,
//! dispatches to subcommands (`run`/`keys`/`secret`), and drives the
//! execution engine. CLI crates may print to stdout/stderr for user-facing
//! streaming output (the workspace denies this by default for library code).

#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
// The workspace denies `panic`/`unwrap`/`expect` in production code; the unit
// test modules use them pervasively and opt out explicitly rather than
// relying on the lint gate skipping test targets. `pedantic` is scoped the
// same way — see `shellflow-core` for the rationale.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]

mod audit;
mod cli;
mod cred_env;
mod diffutil;
mod emit;
mod executor;
mod fsx;
mod host;
mod keys;
mod lint;
mod manifest;
mod preflight;
mod rbatch;
mod secret;
mod secrets;
mod service;
mod service_check;
mod service_diff;
mod service_manifest;
mod service_status;
mod systemd;
#[cfg(feature = "dbus")]
mod systemd_dbus;
mod template;
mod ui;
mod unit;
mod unit_cmd;
mod unit_verify;

use std::{sync::Arc, time::Duration};

use clap::Parser;
use eyre::{Context as _, Result};
use tokio::sync::Mutex;

use crate::{
    cli::{Cli, Command, GlobalFlags, RunArgs},
    executor::{Cancel, RunOutcome, StepStats, execute_plan},
    preflight::{preflight_check, preflight_check_local},
    ui::HostStatus,
};

/// The exit code used when interrupted by a signal.
const EXIT_INTERRUPTED: i32 = 130;

/// How long the executor is given to tear down its children after an
/// interrupt.
///
/// The teardown is what guarantees that no process group survives the run,
/// so the wait is bounded but generous: every child gets a `SIGTERM`, a
/// grace period, and a `SIGKILL`.
const INTERRUPT_GRACE: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();

    let code = match &cli.command {
        None => run_or_deploy(&cli.run, &cli.globals).await,
        Some(Command::Run(args)) => run_or_deploy(args, &cli.globals).await,
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
            let ui = match ui::Ui::new(0, cli.globals.no_color, cli::OutputMode::Stream, None) {
                Ok(ui) => ui,
                Err(err) => {
                    eprintln!("error: {err:#}");
                    return Ok(());
                }
            };
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
        Some(Command::Systemd(cmd)) => match systemd::run(&cmd.command).await {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                err.exit_code()
            }
        },
        Some(Command::Host(cmd)) => match host::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err}");
                err.exit_code()
            }
        },
        Some(Command::Unit(cmd)) => match unit_cmd::run(&cmd.command) {
            Ok(code) => code,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
        Some(Command::Service(cmd)) => match service::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                err.exit_code()
            }
        },
        Some(Command::Audit(cmd)) => match audit::audit(cmd) {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("error: {err:#}");
                1
            }
        },
    };
    report_audit_failures();
    std::process::exit(code);
}

/// Report a truncated audit trail.
///
/// A silently truncated audit log is worse than no audit log: the operator
/// believes the run was recorded in full.
fn report_audit_failures() {
    let failures = ui::audit_write_failures();
    if failures > 0 {
        eprintln!(
            "warning: {failures} line(s) could not be written to the audit log — the trail is \
             incomplete"
        );
    }
}

/// Run a deploy script (the default `run` path).
async fn run_or_deploy(run: &RunArgs, globals: &GlobalFlags) -> i32 {
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

    run_plan(run, globals, plan).await
}

/// Preflight for the `run` path; `--local` needs only `bash`.
fn run_preflight(run: &RunArgs) -> Result<(), String> {
    run_preflight_flags(&run.flags)
}

fn run_preflight_flags(flags: &cli::RunFlags) -> Result<(), String> {
    if flags.local { preflight_check_local() } else { preflight_check() }
}

/// Execute a plan and map the outcome to an exit code.
async fn run_plan(
    run: &RunArgs,
    globals: &GlobalFlags,
    plan: shellflow_core::ExecutionPlan,
) -> i32 {
    let total_steps = plan.steps.len();

    let progress: Arc<Mutex<Vec<StepStats>>> = Arc::new(Mutex::new(Vec::new()));
    let cancel = Cancel::new();

    // The UI is created here, before the executor starts, so the audit-log
    // handle exists for the whole run: an audit trail that cannot be opened
    // must fail the run *before* anything is attempted, and the interrupt
    // summary must be able to reach the same file.
    let ui = match ui::Ui::new(
        run.flags.verbose,
        globals.no_color,
        run.flags.output,
        globals.log_file.clone(),
    ) {
        Ok(ui) => Arc::new(Mutex::new(ui)),
        Err(err) => {
            eprintln!("error: {err:#}");
            return executor::RunError::Config.into_exit_code();
        }
    };
    let log_file = ui.lock().await.log_file();

    // The executor runs in its own task so an interrupt can be handled
    // *cooperatively*: the signal is delivered to the executor, which tears
    // every child process group down and returns normally. Dropping the
    // executor's future instead would abort the host tasks asynchronously,
    // and the process could exit before their process-group guards ran —
    // which is exactly how an orphaned `ssh` survives a Ctrl-C.
    let owned_run = run.clone();
    let owned_progress = Arc::clone(&progress);
    let owned_ui = Arc::clone(&ui);
    let mut executor = tokio::spawn({
        let cancel = cancel.clone();
        async move { execute_plan(&owned_run, plan, owned_progress, cancel, owned_ui).await }
    });

    let outcome = tokio::select! {
        result = &mut executor => match result {
            Ok(outcome) => outcome,
            Err(join_err) => {
                eprintln!("error: the executor stopped unexpectedly: {join_err}");
                RunOutcome::Failed(executor::RunError::Script)
            }
        },
        signal = wait_for_signal() => {
            match signal {
                Ok(()) => {
                    eprintln!("\ninterrupted — aborting; in-flight processes are being terminated");
                    cancel.cancel();
                    // Wait for the teardown: this is what guarantees that no
                    // process group outlives the run.
                    match tokio::time::timeout(INTERRUPT_GRACE, &mut executor).await {
                        Ok(Ok(outcome)) => outcome,
                        Ok(Err(join_err)) => {
                            eprintln!("error: the executor stopped unexpectedly: {join_err}");
                            executor.abort();
                            RunOutcome::Interrupted { total: total_steps, torn_down: false }
                        }
                        Err(_) => {
                            eprintln!("warning: the teardown did not finish in time");
                            // The executor task is still running with live
                            // process groups: abort it so it cannot outlive
                            // the CLI, and report honestly that groups may
                            // still be terminating.
                            executor.abort();
                            RunOutcome::Interrupted { total: total_steps, torn_down: false }
                        }
                    }
                }
                Err(err) => {
                    // The signal handler could not be installed: that is not
                    // an interrupt, and treating it as one would abort the
                    // run with a misleading exit code. The executor task is
                    // already running, so cancel it and wait it out rather
                    // than exiting past live process groups.
                    eprintln!("error: cannot install the signal handler: {err}");
                    cancel.cancel();
                    executor.abort();
                    let _ = executor.await;
                    return executor::RunError::Config.into_exit_code();
                }
            }
        }
    };

    match outcome {
        RunOutcome::Success => 0,
        RunOutcome::Failed(err) => err.into_exit_code(),
        RunOutcome::Interrupted { total, torn_down } => {
            if torn_down {
                eprintln!("interrupted — {total} total steps; in-flight processes were terminated");
            } else {
                eprintln!(
                    "interrupted — {total} total steps; in-flight processes are being terminated"
                );
            }
            let done = progress.lock().await;
            if !done.is_empty() {
                let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
                    done.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
                // The summary goes to the audit trail too: the run's final
                // state is exactly what an operator needs to reconstruct an
                // aborted deploy.
                crate::ui::final_summary(&summary, &log_file);
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
