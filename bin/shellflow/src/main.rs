//! `shellflow` — ultra-fast, shell-native deployment tool.
//!
//! The binary owns the I/O boundary: it parses the CLI, runs preflight,
//! dispatches to subcommands (`run`/`keys`/`secret`), and drives the
//! execution engine. Every human-readable line the tool prints goes through
//! the `ui` module: the `run` path streams through [`ui::Ui`] (masked,
//! audited), and the report subcommands use the `ui::report!` macro (masked).
//! Byte-exact outputs (`secret encrypt`/`decrypt` stdout, `emit` helper dump)
//! bypass the sink by design so bytes survive unchanged. A bare `println!`
//! anywhere but `ui` fails the lint instead of silently bypassing the
//! masker; `eprintln!` is allowed only under a scoped `#[expect]` (fatal
//! banners, error reporters, verify problems, test diagnostics).

// The workspace denies `panic`/`unwrap`/`expect` in production code; the unit
// test modules use them pervasively and opt out explicitly rather than
// relying on the lint gate skipping test targets. `pedantic` is scoped the
// same way — see `shellflow-core` for the rationale.
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
#![cfg_attr(test, allow(clippy::pedantic, clippy::nursery))]
// `main` itself prints the fatal-error and interrupt banners; the executor
// and the library crates never do. The exemption is scoped to the two
// functions that must reach a possibly-broken stderr, not the whole crate,
// so a new `eprintln!` elsewhere still fails the lint.

// The report modules print through `ui::report!`, so none of them needs a
// `print_stdout` exemption: the lint stays live in every one of them.
mod audit;
mod cli;
mod cred_env;
mod diffutil;
mod emit;
mod executor;
mod exit;
mod fsx;
mod host;
mod keys;
mod lint;
mod manifest;
mod preflight;
mod rbatch;
// `secret decrypt`/`encrypt` write exact bytes by design: `write_output`
// bypasses the redacting report sink (plaintext/ciphertext must be byte-exact
// and must not gain a trailing newline), so only the report lines go through
// `ui::report!`. Only stderr keeps a scoped exemption (the temp-file warning).
#[expect(clippy::print_stderr, reason = "secret subcommand warnings reach a broken terminal")]
mod secret;
mod secrets;
mod service;
mod service_check;
mod service_diff;
mod service_manifest;
mod service_status;
mod systemctl;
mod systemd;
#[cfg(feature = "dbus")]
mod systemd_dbus;
mod template;
// `ui` is the output sink itself: it writes through the locked stdout/stderr
// handles (not `println!`), so no print lint fires here by construction.
mod ui;
mod unit;
mod unit_cmd;
mod unit_verify;

use std::{process::ExitCode, sync::Arc, time::Duration};

use clap::Parser;
use eyre::{Context as _, Result};
use tokio::sync::Mutex;

use crate::{
    cli::{Cli, Command, GlobalFlags, RunArgs},
    executor::{Cancel, RunOutcome, StepStats, execute_plan},
    preflight::{preflight_check, preflight_check_local},
    ui::HostStatus,
};

/// How long the executor is given to tear down its children after an
/// interrupt.
///
/// The teardown is what guarantees that no process group survives the run,
/// so the wait is bounded but generous: every child gets a `SIGTERM`, a
/// grace period, and a `SIGKILL`.
const INTERRUPT_GRACE: Duration = Duration::from_secs(15);

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let code = match &cli.command {
        None => run_or_deploy(&cli.run, &cli.globals).await,
        Some(Command::Run(args)) => run_or_deploy(args, &cli.globals).await,
        Some(Command::Keys(cmd)) => match keys::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
        Some(Command::Secret(cmd)) => match secret::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
        Some(Command::Template(cmd)) => {
            match ui::Ui::new(0, cli.globals.no_color, cli::OutputMode::Stream, None) {
                Ok(ui) => match template::run(&cmd.command, &ui) {
                    Ok(()) => 0,
                    Err(err) => {
                        ui::error_line(&err);
                        1
                    }
                },
                // An unwritable audit target or a broken terminal must fail
                // the command; returning `Ok(())` here used to exit 0.
                Err(err) => {
                    ui::error_line(&err);
                    1
                }
            }
        }
        Some(Command::Emit(cmd)) => match emit::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
        Some(Command::CredEnv(cmd)) => match cred_env::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
        Some(Command::Systemd(cmd)) => match systemd::run(cmd.command.clone()).await {
            Ok(()) => 0,
            Err(err) => {
                ui::error_text(&err.to_string());
                err.exit_code()
            }
        },
        Some(Command::Host(cmd)) => match host::run(&cmd.command) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_text(&err.to_string());
                err.exit_code()
            }
        },
        Some(Command::Unit(cmd)) => match unit_cmd::run(&cmd.command) {
            Ok(code) => code,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
        Some(Command::Service(cmd)) => {
            // The service subcommands drive the synchronous `rbatch` SSH
            // batches (blocking writes, blocking line loops, an OS watchdog
            // thread) — blocking work must not sit on a tokio runtime
            // worker. The OS-thread pattern is what `service_status` uses
            // internally; `spawn_blocking` is the entry-point equivalent.
            let command = cmd.command.clone();
            match tokio::task::spawn_blocking(move || service::run(&command)).await {
                Ok(Ok(())) => 0,
                Ok(Err(err)) => {
                    ui::error_text(&err.to_string());
                    err.exit_code()
                }
                Err(join_err) => {
                    ui::error_text(&format!("the service worker stopped unexpectedly: {join_err}"));
                    1
                }
            }
        }
        Some(Command::Audit(cmd)) => match audit::audit(cmd) {
            Ok(()) => 0,
            Err(err) => {
                ui::error_line(&err);
                exit::Code::Plan.code()
            }
        },
    };
    report_truncation();
    // Returning from `main` instead of `std::process::exit` lets every guard
    // that is still alive run its destructor: a captured step's
    // `CaptureFile`, the audit-log handle, the tokio runtime shutdown. The
    // interrupt path relies on `abort()` plus a bounded wait, and that
    // guarantee only holds if exiting does not jump over the teardown.
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}

/// Report a truncated audit trail or a truncated terminal stream.
///
/// A silently truncated audit log is worse than no audit log: the operator
/// believes the run was recorded in full. The same holds for the terminal —
/// a run piped into `head` must not look complete.
#[expect(clippy::print_stderr, reason = "truncation warnings must reach a possibly-broken stderr")]
fn report_truncation() {
    let audit = ui::audit_write_failures();
    if audit > 0 {
        eprintln!(
            "warning: {audit} line(s) could not be written to the audit log — the trail is \
             incomplete"
        );
    }
    let terminal = ui::terminal_write_failures();
    if terminal > 0 {
        eprintln!(
            "warning: {terminal} line(s) could not be written to the terminal — the output \
             stream is incomplete"
        );
    }
}

/// Run a deploy script (the default `run` path).
async fn run_or_deploy(run: &RunArgs, globals: &GlobalFlags) -> i32 {
    // The probes spawn processes and poll them with a blocking sleep, so they
    // must not run on a runtime worker: `main` awaits them here instead.
    let flags = run.flags.clone();
    match tokio::task::spawn_blocking(move || run_preflight_flags(&flags)).await {
        Ok(Ok(())) => {}
        Ok(Err(msg)) => {
            ui::error_text(&msg);
            return exit::Code::Transport.code();
        }
        Err(join_err) => {
            ui::error_text(&format!("the preflight worker stopped unexpectedly: {join_err}"));
            return exit::Code::Transport.code();
        }
    }

    let content = match tokio::fs::read_to_string(&run.script)
        .await
        .wrap_err_with(|| format!("failed to read script `{}`", run.script.display()))
    {
        Ok(content) => content,
        Err(err) => {
            ui::error_line(&err);
            return exit::Code::Plan.code();
        }
    };

    let plan = match shellflow_core::parse_script(&content) {
        Ok(plan) => plan,
        Err(err) => {
            ui::error_text(&err.to_string());
            return exit::Code::Plan.code();
        }
    };

    run_plan(run, globals, plan).await
}

/// Preflight for the `run` path; `--local` needs only `bash`.
fn run_preflight_flags(flags: &cli::RunFlags) -> Result<(), String> {
    if flags.local { preflight_check_local() } else { preflight_check() }
}

/// Execute a plan and map the outcome to an exit code.
#[expect(clippy::print_stderr, reason = "interrupt banners must reach a possibly-broken stderr")]
async fn run_plan(
    run: &RunArgs,
    globals: &GlobalFlags,
    plan: shellflow_core::ExecutionPlan,
) -> i32 {
    let total_steps = plan.steps().len();

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
        run.flags.log_file.clone(),
    ) {
        Ok(ui) => Arc::new(Mutex::new(ui)),
        Err(err) => {
            ui::error_line(&err);
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
                ui::error_text(&format!("the executor stopped unexpectedly: {join_err}"));
                RunOutcome::Failed(executor::RunError::Script)
            }
        },
        signal = wait_for_signal() => {
            match signal {
                Ok(()) => {
                    eprintln!(
                        "\n{}",
                        ui::redact("interrupted — aborting; in-flight processes are being terminated")
                    );
                    cancel.cancel();
                    // Wait for the teardown: this is what guarantees that no
                    // process group outlives the run.
                    match tokio::time::timeout(INTERRUPT_GRACE, &mut executor).await {
                        Ok(Ok(outcome)) => outcome,
                        Ok(Err(join_err)) => {
                            ui::error_text(&format!(
                                "the executor stopped unexpectedly: {join_err}"
                            ));
                            executor.abort();
                            RunOutcome::Interrupted { total: total_steps, torn_down: false }
                        }
                        Err(_) => {
                            eprintln!(
                                "warning: {}",
                                ui::redact("the teardown did not finish in time")
                            );
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
                    ui::error_text(&format!("cannot install the signal handler: {err}"));
                    cancel.cancel();
                    executor.abort();
                    let _ = executor.await;
                    return executor::RunError::Config.into_exit_code();
                }
            }
        }
    };

    match outcome {
        RunOutcome::Success => exit::Code::Success.code(),
        RunOutcome::Failed(err) => err.into_exit_code(),
        RunOutcome::Interrupted { total, torn_down } => {
            let state = if torn_down {
                "in-flight processes were terminated"
            } else {
                "in-flight processes are being terminated"
            };
            eprintln!("{}", ui::redact(&format!("interrupted — {total} total steps; {state}")));
            let done = progress.lock().await;
            if !done.is_empty() {
                let summary: Vec<(usize, Duration, Vec<HostStatus>)> =
                    done.iter().map(|s| (s.index, s.elapsed, s.statuses.clone())).collect();
                // The summary goes to the audit trail too: the run's final
                // state is exactly what an operator needs to reconstruct an
                // aborted deploy.
                crate::ui::final_summary(&summary, &log_file);
            }
            exit::Code::Interrupted.code()
        }
    }
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
