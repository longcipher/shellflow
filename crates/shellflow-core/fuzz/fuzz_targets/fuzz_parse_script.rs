#![no_main]
//! Fuzz target: the playbook parser.
//!
//! A playbook is a shell script, so the input is untrusted by definition: a
//! typo, a here-document, or a stray `# @` line must produce either a clean
//! [`ParseError`] or a plan — never a panic, never a hang, and never a plan
//! that changes when the same bytes are parsed again.

use libfuzzer_sys::fuzz_target;
use shellflow_core::{Target, parse_script, resolve_hosts};

fuzz_target!(|data: &[u8]| {
    // The parser is a text scanner; skip inputs that are not UTF-8 rather
    // than treating them as a finding (the CLI always reads a `String`).
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let Ok(plan) = parse_script(text) else {
        return;
    };

    // Determinism: parsing is a pure function, so the same bytes must always
    // yield the same plan.
    let again = parse_script(text).expect("parsing must be deterministic");
    assert_eq!(plan.steps().len(), again.steps().len(), "step count must be stable");
    assert!(plan == again, "parsing must be deterministic");

    // A step's target must resolve without panicking. `resolve_hosts` is where
    // a raw ssh spec is parsed, which is the other byte-level scanner.
    for step in plan.steps() {
        if let Some(target) = step.target_text() {
            let _ = resolve_hosts(&plan, &Target::new(target), &[]);
        }
    }

    // Restriction to a host nobody declared must be a clean error (exit 1),
    // never a panic.
    for step in plan.steps() {
        if let Some(target) = step.target_text() {
            let _ = resolve_hosts(&plan, &Target::new(target), &["no-such-host".to_string()]);
        }
    }
});
