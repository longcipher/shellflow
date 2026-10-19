//! Shell-safe environment rendering, `@export` capture parsing, and secret
//! redaction helpers.
//!
//! [`render_env`] and [`parse_capture_records`] are the two halves of one
//! protocol: the first renders the env header that precedes every payload, the
//! second parses the `NAME=VALUE\0` records a local block writes back so that
//! `@export` state survives a step boundary (design §7.6).

use std::collections::BTreeMap;

use crate::error::CaptureError;

/// The placeholder used when redacting known secret values.
pub const MASK: &str = "***";

/// The record separator used by the `@export` capture file.
///
/// NUL — not `\n` — is deliberate. A shell variable may legally contain a
/// newline, so a newline-delimited format lets one exported value forge
/// another (and silently truncates a legitimately multi-line value). NUL
/// cannot occur inside a shell value, which makes it an unambiguous record
/// boundary that needs no escaping (design §7.6).
pub const CAPTURE_SEPARATOR: u8 = 0;

/// Parse the NUL-delimited `@export` capture records written by the runner.
///
/// Records have the form `NAME=VALUE\0`; empty records (including the trailing
/// one after the final separator) are skipped. When a name repeats, the last
/// record wins, matching bash `source` semantics.
///
/// # Errors
///
/// Returns [`CaptureError::MissingSeparator`] for a record without `=`, and
/// [`CaptureError::NotUtf8`] when a name or value is not valid UTF-8.
pub fn parse_capture_records(bytes: &[u8]) -> Result<BTreeMap<String, String>, CaptureError> {
    let mut out = BTreeMap::new();
    for record in bytes.split(|&b| b == CAPTURE_SEPARATOR) {
        if record.is_empty() {
            continue;
        }
        let Some(eq) = record.iter().position(|&b| b == b'=') else {
            return Err(CaptureError::MissingSeparator);
        };
        let (name, value) = record.split_at(eq);
        let name = std::str::from_utf8(name).map_err(|_| CaptureError::NotUtf8)?;
        let value = std::str::from_utf8(&value[1..]).map_err(|_| CaptureError::NotUtf8)?;
        out.insert(name.to_string(), value.to_string());
    }
    Ok(out)
}

/// Single-quote a value for safe inclusion in a `bash` export line.
///
/// A literal `'` is escaped as `'\''`, which is valid inside single quotes.
#[must_use]
pub fn shell_quote_single(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Render already-resolved `(key, value)` pairs as `export` lines.
///
/// The returned string is the payload header that precedes any `set -x`
/// tracing, so the exported values themselves are never traced.
#[must_use]
pub fn render_env(entries: &[(String, String)]) -> String {
    let mut out = String::new();
    for (key, value) in entries {
        out.push_str("export ");
        out.push_str(key);
        out.push('=');
        out.push_str(&shell_quote_single(value));
        out.push_str(";\n");
    }
    out
}

/// Order and de-duplicate a mask set for [`mask_line`].
///
/// Sorting longest-first is what stops a value that is a prefix of another
/// (e.g. `abc` vs `abcdef`) from leaving the longer secret's tail exposed. It
/// is done **once per run**, not once per output line: this function is on the
/// hot path for every streamed line, and a playbook can register hundreds of
/// `@secrets` values. The result is returned owned so the caller can store it
/// directly and reuse it for the whole run.
#[must_use]
pub fn prepare_masks(secrets: &[String]) -> Vec<String> {
    let mut ordered: Vec<&str> =
        secrets.iter().filter(|s| !s.is_empty()).map(String::as_str).collect();
    ordered.sort_unstable_by_key(|a| std::cmp::Reverse(a.len()));
    ordered.dedup();
    ordered.into_iter().map(ToOwned::to_owned).collect()
}

/// Redact every occurrence of the known secrets in `line` with [`MASK`].
///
/// `masks` **must** come from [`prepare_masks`] (longest-first, de-duplicated);
/// an arbitrary slice does not satisfy that ordering.
#[must_use]
pub fn mask_line<S: AsRef<str>>(line: &str, masks: &[S]) -> String {
    if masks.is_empty() {
        return line.to_string();
    }
    let mut out = line.to_string();
    for secret in masks {
        out = out.replace(secret.as_ref(), MASK);
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::{prop_assert, prop_assert_eq};

    use super::{
        CAPTURE_SEPARATOR, MASK, mask_line, parse_capture_records, prepare_masks, render_env,
        shell_quote_single,
    };

    #[test]
    fn parses_basic_capture_records() {
        let records = b"VERSION=abc123\0SVC=myapp\0";
        let parsed = parse_capture_records(records).expect("records parse");
        assert_eq!(parsed.get("VERSION").map(String::as_str), Some("abc123"));
        assert_eq!(parsed.get("SVC").map(String::as_str), Some("myapp"));
    }

    #[test]
    fn capture_value_may_contain_newline_and_equals() {
        // The reason the format is NUL-delimited: a newline inside one value
        // must not truncate it, and must not look like a second record.
        let records = b"A=first\nsecond=third\0B=x=y=z\0";
        let parsed = parse_capture_records(records).expect("records parse");
        assert_eq!(parsed.get("A").map(String::as_str), Some("first\nsecond=third"));
        assert_eq!(parsed.get("B").map(String::as_str), Some("x=y=z"));
        assert!(!parsed.contains_key("second"), "an embedded line must not become a record");
    }

    #[test]
    fn capture_value_may_be_empty() {
        let records = b"A=\0B=v\0";
        let parsed = parse_capture_records(records).expect("records parse");
        assert_eq!(parsed.get("A").map(String::as_str), Some(""));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn capture_empty_input_yields_empty_map() {
        let parsed = parse_capture_records(b"").expect("empty input parses");
        assert!(parsed.is_empty());
    }

    #[test]
    fn capture_last_record_wins() {
        let records = b"A=first\0A=second\0";
        let parsed = parse_capture_records(records).expect("records parse");
        assert_eq!(parsed.get("A").map(String::as_str), Some("second"));
    }

    #[test]
    fn capture_missing_separator_is_an_error() {
        assert!(matches!(
            parse_capture_records(b"A=v\0NOSEP\0"),
            Err(crate::error::CaptureError::MissingSeparator)
        ));
    }

    #[test]
    fn capture_invalid_utf8_is_an_error() {
        let mut bytes = b"A=".to_vec();
        bytes.push(0xff);
        bytes.push(CAPTURE_SEPARATOR);
        assert!(matches!(parse_capture_records(&bytes), Err(crate::error::CaptureError::NotUtf8)));
    }

    #[test]
    fn quotes_plain_value() {
        assert_eq!(shell_quote_single("abc123"), "'abc123'");
    }

    #[test]
    fn quotes_embedded_single_quote() {
        assert_eq!(shell_quote_single("a'b"), "'a'\\''b'");
    }

    #[test]
    fn renders_export_lines() {
        let entries = vec![
            ("KEY".to_string(), "value".to_string()),
            ("SECRET".to_string(), "s3cr3t".to_string()),
        ];
        let out = render_env(&entries);
        assert_eq!(out, "export KEY='value';\nexport SECRET='s3cr3t';\n");
    }

    #[test]
    fn renders_empty() {
        assert_eq!(render_env(&[]), "");
    }

    #[test]
    fn masks_secret_occurrences() {
        let line = "export DB_PASSWORD='s3cr3t';";
        let secrets = vec!["s3cr3t".to_string()];
        let redacted = mask_line(line, &prepare_masks(&secrets));
        assert_eq!(redacted, "export DB_PASSWORD='***';");
    }

    #[test]
    fn mask_longest_first_avoid_prefix_leak() {
        // The shorter secret is a prefix of the longer one. Masking longest
        // first must not leave the longer secret's tail exposed.
        let line = "KEY=abcdef KEY_LONG=abcdefXYZ";
        let secrets = vec!["abcdef".to_string(), "abcdefXYZ".to_string()];
        let redacted = mask_line(line, &prepare_masks(&secrets));
        assert_eq!(redacted, "KEY=*** KEY_LONG=***");
        assert!(!redacted.contains("XYZ"));
    }

    #[test]
    fn mask_dedups_repeated_values() {
        let line = "A=secret B=secret";
        let secrets = vec!["secret".to_string(), "secret".to_string()];
        let redacted = mask_line(line, &prepare_masks(&secrets));
        assert_eq!(redacted, "A=*** B=***");
        assert_eq!(prepare_masks(&secrets).len(), 1, "duplicate secrets must be collapsed once");
    }

    #[test]
    fn mask_ignores_empty_secret() {
        let secrets = vec![String::new()];
        assert_eq!(mask_line("hello", &prepare_masks(&secrets)), "hello");
    }

    #[test]
    fn prepare_masks_is_order_independent() {
        let forward = vec!["bbb".to_string(), "a".to_string(), "cc".to_string()];
        let backward = vec!["cc".to_string(), "a".to_string(), "bbb".to_string()];
        assert_eq!(prepare_masks(&forward), prepare_masks(&backward));
        assert_eq!(prepare_masks(&forward), vec!["bbb", "cc", "a"], "longest first");
    }

    #[test]
    fn mask_is_stable_constant() {
        assert_eq!(MASK, "***");
    }

    /// Inverse of [`shell_quote_single`] for property testing: returns `None`
    /// when the input is not a well-formed single-quoted shell word.
    fn unquote_single(quoted: &str) -> Option<String> {
        let inner = quoted.strip_prefix('\'')?.strip_suffix('\'')?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch != '\'' {
                out.push(ch);
                continue;
            }
            // A literal quote is emitted as the 4-char sequence `'\''`.
            for expected in ['\\', '\'', '\''] {
                if chars.next()? != expected {
                    return None;
                }
            }
            out.push('\'');
        }
        Some(out)
    }

    proptest::proptest! {
        /// The capture protocol round-trips values containing the characters
        /// that would break a newline- or `=`-delimited format: an exported
        /// value can never forge a sibling record, and never truncates.
        #[test]
        fn capture_round_trips_delimiter_bearing_values(
            (name, value) in ("[A-Za-z_][A-Za-z0-9_]{0,8}", "[^\0]{0,24}"),
        ) {
            let mut records = Vec::new();
            records.extend_from_slice(name.as_bytes());
            records.push(b'=');
            records.extend_from_slice(value.as_bytes());
            records.push(CAPTURE_SEPARATOR);

            let parsed = parse_capture_records(&records)
                .map_err(|e| proptest::prelude::TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(parsed.get(name.as_str()).map(String::as_str), Some(value.as_str()));
            prop_assert_eq!(parsed.len(), 1, "exactly one record must be produced");
        }

        /// Quoting is lossless: any value survives a shell round-trip, so a
        /// value containing `'`, spaces, or metacharacters reaches the remote
        /// byte-for-byte.
        #[test]
        fn shell_quote_single_round_trips(
            value in "[a-zA-Z0-9 '\"$`\\\\;|&*?\t/._-]{0,40}",
        ) {
            let quoted = shell_quote_single(&value);
            prop_assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            prop_assert_eq!(unquote_single(&quoted), Some(value));
        }

        /// A known secret never survives masking, and the result is
        /// independent of the order the secrets were collected in.
        #[test]
        fn mask_line_removes_every_secret_and_is_order_independent(
            // Each secret carries a marker character unique to it, so no
            // secret can be a substring of another (the case `mask_line`
            // handles by masking longest-first).
            secrets in proptest::collection::vec(("[A-Z]", "[a-z0-9]{0,8}"), 1..5),
            filler in "[a-z ]{0,20}",
        ) {
            let values: Vec<String> =
                secrets.iter().map(|(marker, tail)| format!("s{marker}{tail}")).collect();
            let line = values.join(&filler);
            let masked = mask_line(&line, &prepare_masks(&values));
            for secret in &values {
                prop_assert!(
                    !masked.contains(secret.as_str()),
                    "secret leaked through masking: {masked:?}"
                );
            }
            let mut reversed = values.clone();
            reversed.reverse();
            // `prepare_masks` must normalise order away, so both give the same line.
            prop_assert_eq!(&masked, &mask_line(&line, &prepare_masks(&reversed)));
        }

        /// Masking twice is the same as masking once: an operator cannot
        /// re-introduce a secret by re-running the redaction pass.
        #[test]
        fn masking_is_idempotent(
            secrets in proptest::collection::vec(("[A-Z]", "[a-z0-9]{0,8}"), 1..4),
            filler in "[a-z ]{0,16}",
        ) {
            let values: Vec<String> =
                secrets.iter().map(|(marker, tail)| format!("s{marker}{tail}")).collect();
            let line = values.join(&filler);
            let masks = prepare_masks(&values);
            let once = mask_line(&line, &masks);
            prop_assert_eq!(mask_line(&once, &masks), once);
        }

        /// `render_env` emits exactly one `export` line per pair, keys are
        /// never quoted or mangled, and masking the rendered payload with its
        /// own values redacts every one of them.
        #[test]
        fn render_env_is_one_line_per_pair(
            entries in proptest::collection::vec(("[A-Z_][A-Z0-9_]{0,8}", "[a-zA-Z0-9/_-]{0,20}"), 0..6),
        ) {
            let rendered = render_env(&entries);
            prop_assert_eq!(rendered.lines().count(), entries.len());
            for (key, value) in &entries {
                // Built outside the macro: `prop_assert!` re-wraps its
                // arguments in `concat!`, which would swallow `{}` here.
                let needle = format!("export {}=", key);
                let quoted = shell_quote_single(value);
                prop_assert!(rendered.contains(&needle));
                prop_assert!(rendered.contains(&quoted));
            }
            let values: Vec<String> = entries.iter().map(|(_, v)| v.clone()).collect();
            let masked = mask_line(&rendered, &prepare_masks(&values));
            for value in values.iter().filter(|v| !v.is_empty() && **v != MASK) {
                prop_assert!(
                    !masked.contains(value.as_str()),
                    "value survived masking: {masked:?}"
                );
            }
        }
    }
}
