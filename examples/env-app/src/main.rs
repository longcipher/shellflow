//! Env App example — plain environment-variable configuration (no encryption).
//!
//! The simple baseline many deployments start with: all configuration,
//! including sensitive-looking values, arrives as plain environment variables
//! via `EnvironmentFile=` in the unit. Nothing here is encrypted; values are
//! readable on the target disk (0600 root) and inside the process environment.
//!
//! Compare with `examples/secret-app`, which feeds the same shape of
//! configuration through age-encrypted env files and host-key-bound systemd
//! credentials instead.
//!
//! Required environment variables:
//!   - `APP_GREETING` — message to print
//!   - `APP_TOKEN`    — a token the app only validates, never prints

// A CLI demo app legitimately prints to stdout/stderr.
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::env;

fn main() {
    let keys = ["APP_GREETING", "APP_TOKEN"];
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

    println!("--- env-app ---");
    println!("LOG_LEVEL={log_level}");
    println!();

    let mut all_ok = true;
    for key in &keys {
        match env::var(key) {
            Ok(value) if value.len() >= 4 => {
                // Never print the value: only its length and a masked preview.
                let masked =
                    format!("{}{}", &value[..2], "*".repeat(value.len().saturating_sub(2)));
                println!("{key}={masked} (len={})", value.len());
            }
            Ok(_) => {
                eprintln!("!! {key} is set but too short (must be >= 4 chars)");
                all_ok = false;
            }
            Err(_) => {
                eprintln!("!! {key} is not set");
                all_ok = false;
            }
        }
    }

    if all_ok {
        println!();
        println!("env-app: all configuration present (plain env, no encryption)");
    } else {
        std::process::exit(1);
    }
}
