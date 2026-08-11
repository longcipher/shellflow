//! Demo Secret App — reads sensitive configuration from environment variables.
//!
//! This is a typical third-party / closed-source application pattern: it reads
//! all configuration from environment variables, expecting them to be injected
//! by the runtime environment (systemd with `ImportCredential=` + `cred-wrap`).
//!
//! Required environment variables:
//!   - `API_KEY`       — API authentication key
//!   - `API_SECRET`    — API signing secret
//!   - `DB_PASSWORD`   — database password
//!
//! Optional:
//!   - `LOG_LEVEL`     — log verbosity (default: info)

#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]

use std::env;

/// Mask a value for safe display: show only the first 4 and last 4 characters.
fn mask(value: &str) -> String {
    if value.len() <= 8 {
        "****".to_string()
    } else {
        let prefix: String = value.chars().take(4).collect();
        let suffix: String =
            value.chars().rev().take(4).collect::<String>().chars().rev().collect();
        format!("{prefix}...{suffix}")
    }
}

/// Read a required env var, returning `None` if missing.
fn read_secret(key: &str) -> Option<String> {
    match env::var(key) {
        Ok(v) => Some(v),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            eprintln!("[demo] ERROR: {key} contains non-unicode bytes");
            None
        }
    }
}

fn main() {
    let secrets = ["API_KEY", "API_SECRET", "DB_PASSWORD"];
    let log_level = env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

    println!("--- demo-secret-app ---");
    println!("LOG_LEVEL={log_level}");
    println!();

    let mut all_ok = true;
    for key in &secrets {
        match read_secret(key) {
            Some(val) => {
                println!(
                    "  {key}={masked} (len={len})",
                    key = key,
                    masked = mask(&val),
                    len = val.len()
                );
            }
            None => {
                eprintln!("  {key}=<MISSING>");
                all_ok = false;
            }
        }
    }

    println!();
    if all_ok {
        println!("All secrets present. App is ready.");
    } else {
        eprintln!("WARNING: one or more secrets are missing — check env setup.");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_short() {
        assert_eq!(mask("12345678"), "****");
        assert_eq!(mask("short"), "****");
    }

    #[test]
    fn test_mask_long() {
        let m = mask("abcdefghijklmnop");
        assert_eq!(m, "abcd...mnop");
    }

    #[test]
    fn test_mask_exact_eight() {
        assert_eq!(mask("12345678"), "****");
    }
}
