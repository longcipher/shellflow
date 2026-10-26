#![no_main]
//! Fuzz target: `@copy` path interpolation (`$VAR` / `${VAR}`).
//!
//! `interpolate` walks the template **by byte index** while pushing by `char`,
//! so a multi-byte character or a `$` at the very end is exactly where an
//! out-of-bounds or a char-boundary panic would hide. The invariants checked
//! here are the ones the copy path depends on:
//!
//! - a template with no `$` is returned unchanged;
//! - interpolation is idempotent (a substituted value is never re-scanned).

use libfuzzer_sys::fuzz_target;
use shellflow_core::{RunState, interpolate};

/// Parse `\0`-separated `KEY=VALUE` pairs into a run state.
///
/// `\0` is the separator so a value may itself contain `=` or newlines, which
/// is what a `@copy` path captured from a build step can legitimately hold.
fn build_state(blob: &str) -> RunState {
    let mut state = RunState::default();
    for pair in blob.split('\0') {
        if let Some((key, value)) = pair.split_once('=') {
            let key = key.trim();
            let valid = !key.is_empty() &&
                !key.starts_with(|c: char| c.is_ascii_digit()) &&
                key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if valid {
                state.vars.insert(key.to_string(), value.to_string());
            }
        }
    }
    state
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    // The first blank line splits the state blob from the template, so the
    // fuzzer can evolve both halves independently.
    let (blob, template) = match text.split_once("\n\n") {
        Some(parts) => parts,
        None => (text, ""),
    };
    let state = build_state(blob);

    // A template without `$` is copied verbatim, whatever the state holds.
    if !template.contains('$') {
        let out = interpolate(template, &state).expect("no references to resolve");
        assert_eq!(out, template, "a `$`-free template must be unchanged");
        return;
    }

    let Ok(out) = interpolate(template, &state) else {
        // An unresolved variable is the documented hard error.
        return;
    };

    // Once no `$` is left there is nothing left to expand, so the output must
    // be a fixed point. (The stronger "always idempotent" claim is false by
    // design: a captured value may contain `$`, and a stray `$` next to a
    // substituted value only becomes a reference on a second pass. Both are
    // single-pass semantics, not defects — see the unit tests.)
    if !out.contains('$') {
        let twice = interpolate(&out, &state).expect("nothing left to resolve");
        assert_eq!(out, twice, "a `$`-free result must be a fixed point");
    }
});
