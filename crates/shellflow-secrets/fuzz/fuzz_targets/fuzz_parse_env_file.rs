#![no_main]
//! Fuzz target: the `KEY=VALUE` env-file parser.
//!
//! The plaintext fed to this parser is the *decrypted* payload of an
//! `.env.age` file, so its bytes are attacker-influenced in the threat model
//! (a corrupted or hostile ciphertext still decrypts under a stolen identity
//! in some failure modes). The invariants checked here are the ones every
//! caller relies on:
//!
//! - parsing never panics, whatever the bytes;
//! - every accepted key is a valid shell identifier — a key that is not would produce an
//!   unassignable `export` line in a remote payload;
//! - parsing is deterministic;
//! - a file with no assignment cannot produce pairs.

use libfuzzer_sys::fuzz_target;
use shellflow_secrets::env::parse_env_file;

/// True for `[A-Za-z_][A-Za-z0-9_]*` — the shape `export KEY=` requires.
fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fuzz_target!(|data: &[u8]| {
    // The parser is a text scanner over the decrypted payload; the CLI always
    // hands it a `String`, so non-UTF-8 input is out of contract.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(pairs) = parse_env_file(text) else {
        // A malformed line is a clean, line-numbered error.
        return;
    };

    for (key, _) in &pairs {
        assert!(is_valid_var_name(key), "parser accepted an unusable variable name: {key:?}");
    }

    // Determinism: the same bytes must always produce the same pairs.
    let again = parse_env_file(text).expect("parsing must be deterministic");
    assert!(pairs == again, "parsing must be deterministic");

    // No `=` anywhere means no assignment could have been parsed.
    if !text.contains('=') {
        assert!(pairs.is_empty(), "no assignment in input, yet pairs were produced");
    }
});
