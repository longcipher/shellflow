//! Shell-safe environment rendering, `@export` capture parsing, and secret
//! redaction helpers.
//!
//! [`render_env`] and [`parse_capture_records`] are the two halves of one
//! protocol: the first renders the env header that precedes every payload, the
//! second parses the `NAME=VALUE\0` records a local block writes back so that
//! `@export` state survives a step boundary (design §7.6).

use std::{collections::BTreeMap, sync::Arc};

// The two text rules and the shell-identifier rule live in the DSL crate,
// which owns the grammar that reads them. They are re-exported here so the
// runtime and the grammar cannot drift apart.
pub use shellflow_dsl::{is_valid_var_name, shell_quote_single, strip_surrounding_quotes};

use crate::error::{CaptureError, RenderEnvError};

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
/// Returns [`CaptureError::MissingSeparator`] for a record without `=`,
/// [`CaptureError::NotUtf8`] when a name or value is not valid UTF-8, and
/// [`CaptureError::UnexpectedVar`] when `allowed` is given and a record names
/// a variable outside it, or when a name is not a valid shell identifier.
pub fn parse_capture_records(bytes: &[u8]) -> Result<BTreeMap<String, String>, CaptureError> {
    parse_capture_records_checked(bytes, None)
}

/// Parse capture records, optionally rejecting names outside `allowed`.
///
/// When `allowed` is `Some`, every record name must be a member of it;
/// otherwise [`CaptureError::UnexpectedVar`] is returned. This is the
/// allow-list check the executor needs: the shell block can write arbitrary
/// `NAME=VALUE\0` lines, and only names the playbook exported may be trusted.
pub fn parse_capture_records_checked(
    bytes: &[u8],
    allowed: Option<&[String]>,
) -> Result<BTreeMap<String, String>, CaptureError> {
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
        if name.is_empty() || !is_valid_var_name(name) {
            return Err(CaptureError::UnexpectedVar { name: name.to_string() });
        }
        if let Some(allowed) = allowed &&
            !allowed.iter().any(|item| item == name)
        {
            return Err(CaptureError::UnexpectedVar { name: name.to_string() });
        }
        out.insert(name.to_string(), value.to_string());
    }
    Ok(out)
}

/// Render already-resolved `(key, value)` pairs as `export` lines.
///
/// The returned string is the payload header that precedes any `set -x`
/// tracing, so the exported values themselves are never traced.
///
/// # Errors
///
/// Returns [`RenderEnvError::InvalidKey`] when a key is not a shell
/// identifier. The value is single-quoted, but the key is written verbatim
/// into shell source that is streamed to a remote host, so a key like
/// `A; rm -rf /` would inject shell into the payload. Every key source
/// validates the name today; this check keeps that guarantee local to the
/// function that owns the quoting, so a future key source cannot become a
/// remote command-injection primitive.
pub fn render_env(entries: &[(String, String)]) -> Result<String, RenderEnvError> {
    let mut out = String::new();
    for (key, value) in entries {
        if !is_valid_var_name(key) {
            return Err(RenderEnvError::InvalidKey { name: key.clone() });
        }
        out.push_str("export ");
        out.push_str(key);
        out.push('=');
        out.push_str(&shell_quote_single(value));
        out.push_str(";\n");
    }
    Ok(out)
}

/// Order and de-duplicate a mask set for [`mask_line`].
///
/// Sorting longest-first is what stops a value that is a prefix of another
/// (e.g. `abc` vs `abcdef`) from leaving the longer secret's tail exposed. It
/// is done **once per run**, not once per output line: this function is on the
/// hot path for every streamed line, and a playbook can register hundreds of
/// `@secrets` values. The result is returned owned so the caller can store it
/// directly and reuse it for the whole run.
///
/// Values of the same length are ordered by their content, so the set — and
/// with it every tie the masker has to break — is the same on every run and
/// on every host, whatever order the `@secrets` entries arrived in.
#[must_use]
pub fn prepare_masks(secrets: &[String]) -> Vec<String> {
    let mut ordered: Vec<&str> =
        secrets.iter().filter(|s| !s.is_empty()).map(String::as_str).collect();
    ordered.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
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
        // An empty value would be replaced *everywhere*: `replace("")` cuts
        // the line between every character.
        if secret.as_ref().is_empty() {
            continue;
        }
        out = out.replace(secret.as_ref(), MASK);
    }
    out
}

/// Whether `c` is part of a shell-style identifier.
///
/// Shell identifiers are ASCII (`[A-Za-z0-9_]`), so a non-ASCII letter is a
/// delimiter: the token next to it stands alone to a shell.
const fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Redact a below-threshold secret that appears as a standalone token.
///
/// A value shorter than the masking threshold cannot be redacted with a
/// global substring replace (that would shred unrelated output), but it is
/// still a secret. This replaces the value only where it is delimited by
/// non-word characters, so `pin=12345`, `v=abc` and `export PIN='12345'`
/// are redacted while `order=123456` and `abcdef` are left alone.
#[must_use]
pub fn mask_token(line: &str, secret: &str) -> String {
    if secret.is_empty() {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(idx) = rest.find(secret) {
        let (before, after) = rest.split_at(idx);
        let tail = &after[secret.len()..];
        let left_ok = before.chars().next_back().is_none_or(|c| !is_word(c));
        let right_ok = tail.chars().next().is_none_or(|c| !is_word(c));
        out.push_str(before);
        out.push_str(if left_ok && right_ok { MASK } else { secret });
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Redact `KEY=value`, `KEY='value'` and `KEY="value"` for one secret.
///
/// The key is matched case-insensitively and as a whole identifier, because a
/// playbook routinely prints the value under a different label than the
/// environment key (`PIN` vs `pin`).
#[must_use]
pub fn mask_keyed(line: &str, key: &str, value: &str) -> String {
    if key.is_empty() || value.is_empty() {
        return line.to_string();
    }
    let mut out = line.to_string();
    for suffix in [format!("={value}"), format!("='{value}'"), format!("=\"{value}\"")] {
        out = replace_keyed(&out, key, &suffix);
    }
    out
}

/// Replace every `IDENT<suffix>` occurrence whose identifier is `key`.
fn replace_keyed(line: &str, key: &str, suffix: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(idx) = rest.find(suffix) {
        let (before, after) = rest.split_at(idx);
        let ident_start = before
            .char_indices()
            .rev()
            .find(|(_, c)| !is_word(*c))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let ident = &before[ident_start..];
        out.push_str(before);
        if ident.eq_ignore_ascii_case(key) {
            // `before` already ends with the identifier.
            out.push('=');
            out.push_str(MASK);
        } else {
            out.push_str(suffix);
        }
        rest = &after[suffix.len()..];
    }
    out.push_str(rest);
    out
}

/// Minimum number of characters a line's trailing fragment must match before
/// it is redacted in place.
///
/// A line that ends with the first character of a secret matches by chance
/// (any secret starting with `s` matches every line ending in `s`), and
/// replacing one character with `***` on every such line would make the
/// output unreadable. Four characters is long enough that a chance match is
/// rare and short enough that a real split secret is still fully covered.
///
/// A split whose prefix is *shorter* than this still has its continuation
/// redacted (see [`SecretMasker::redact_line`]), so the complete value never
/// appears either way — only a fragment of at most three characters can.
const MIN_PREFIX_REDACT: usize = 4;

/// Byte offsets of the proper prefixes of `s`, longest first.
///
/// Each offset is the byte length of the prefix made of the first *k*
/// characters, for every *k* below the character count of `s`.
fn prefix_boundaries(s: &str) -> Vec<usize> {
    let mut out: Vec<usize> = s.char_indices().skip(1).map(|(i, _)| i).collect();
    out.reverse();
    out
}

/// Replace the byte ranges of `line` with [`MASK`], merging overlaps.
fn apply_ranges(line: &str, ranges: &[(usize, usize)]) -> String {
    if ranges.is_empty() {
        return line.to_string();
    }
    let mut sorted: Vec<(usize, usize)> = ranges.to_vec();
    sorted.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, len) in sorted {
        let end = start + len;
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = String::with_capacity(line.len());
    let mut cursor = 0;
    for (start, end) in merged {
        // `get` yields `None` for an overlapping range and an empty slice
        // for a range that starts at the cursor — both mean "no gap".
        if let Some(gap) = line.get(cursor..start) {
            out.push_str(gap);
        }
        out.push_str(MASK);
        cursor = cursor.max(end);
    }
    if let Some(rest) = line.get(cursor..) {
        out.push_str(rest);
    }
    out
}

/// Redacts known secret values from program output.
///
/// Two rules apply:
///
/// 1. **Long values** (at or above the masking threshold) are redacted with a plain substring
///    replacement, but the matcher is *stateful across lines*: a secret that a target program split
///    across two output lines — `fold`, a pager, a progress bar — is redacted as a whole instead of
///    leaking two fragments that reassemble into the original value in the console scrollback or in
///    the `--log-file` audit trail.
/// 2. **Short values** (below the threshold) are redacted with narrow rules that cannot shred
///    unrelated output: the value is replaced where it stands alone as a token, or where it appears
///    as `KEY=value`.
///
/// One masker belongs to one output stream. Sharing it between hosts would
/// let a line from one host consume the pending state of another.
#[derive(Clone, Debug)]
pub struct SecretMasker {
    /// Long values, longest-first and de-duplicated.
    masks: Arc<Vec<String>>,
    /// Proper-prefix byte offsets of each long value, longest first.
    boundaries: Arc<Vec<Vec<usize>>>,
    /// Short values as `(key, value)` pairs.
    shorts: Arc<Vec<(String, String)>>,
    /// Values whose prefix was seen at the end of an earlier line, with the
    /// number of bytes of the value already accounted for.
    pending: Vec<(String, usize)>,
}

impl SecretMasker {
    /// Create a masker for the given values.
    ///
    /// `masks` holds the values at or above the masking threshold (longest
    /// first, de-duplicated — see [`prepare_masks`]); `shorts` holds the
    /// `(key, value)` pairs below it.
    #[must_use]
    pub fn new(masks: Arc<Vec<String>>, shorts: Arc<Vec<(String, String)>>) -> Self {
        let boundaries = Arc::new(masks.iter().map(|s| prefix_boundaries(s)).collect());
        Self { masks, boundaries, shorts, pending: Vec::new() }
    }

    /// Redact a standalone fragment of text (a note, a preview, a log header).
    ///
    /// Unlike [`Self::redact_line`] this keeps no state: a note is a
    /// self-contained string, never a fragment of a longer stream.
    #[must_use]
    pub fn redact_text(&self, text: &str) -> String {
        let mut out = mask_line(text, &self.masks);
        for (key, value) in self.shorts.iter() {
            out = mask_token(&out, value);
            out = mask_keyed(&out, key, value);
        }
        out
    }

    /// Redact one line of program output.
    ///
    /// Stateful: the line is redacted in the context of the lines before it,
    /// so a value that was split across a line boundary is redacted as a
    /// whole. The state is per stream — see [`Self`].
    #[must_use]
    pub fn redact_line(&mut self, line: &str) -> String {
        let mut ranges: Vec<(usize, usize)> = Vec::new();

        // 1. A value whose prefix ended on an earlier line continues here.
        let mut kept: Vec<(String, usize)> = Vec::new();
        if line.is_empty() {
            // An empty line carries no bytes, so it cannot continue or break
            // a value: keep every pending prefix for the next non-empty line.
            kept = std::mem::take(&mut self.pending);
            self.pending = kept;
            // Still run the narrow rules so `KEY=` on an empty line stays
            // consistent (a no-op today, but explicit).
            let mut out = line.to_string();
            for (key, value) in self.shorts.iter() {
                out = mask_token(&out, value);
                out = mask_keyed(&out, key, value);
            }
            return out;
        }
        for (secret, consumed) in std::mem::take(&mut self.pending) {
            let Some(rest) = secret.get(consumed..) else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            if !line.is_empty() && rest.starts_with(line) {
                // The whole line continues the value.
                ranges.push((0, line.len()));
                let consumed = consumed + line.len();
                // Only a *partial* value is worth remembering: once the whole
                // value has been seen, there is nothing left to continue.
                if secret.get(consumed..).is_some_and(|remainder| !remainder.is_empty()) {
                    kept.push((secret, consumed));
                }
            } else if line.starts_with(rest) {
                // The line completes the value and continues past it.
                ranges.push((0, rest.len()));
            }
            // Otherwise the continuation broke and the pending is dropped: the
            // earlier prefix was redacted in place, or is a bounded fragment.
        }
        self.pending = kept;

        // 2. Complete occurrences inside this line.
        ranges.extend(self.occurrences(line));

        // 3. A value that starts at the tail of this line.
        if let Some((prefix_len, secret)) = self.tail_prefix(line) {
            let start = line.len() - prefix_len;
            if prefix_len >= MIN_PREFIX_REDACT {
                ranges.push((start, prefix_len));
            }
            // The continuation is tracked even when the prefix was too
            // short to redact in place: redacting the continuation is what
            // keeps the complete value out of the output. It is tracked
            // unconditionally, so a prefix that another range already
            // covers cannot smuggle its continuation through unredacted.
            self.pending.push((secret, prefix_len));
        }

        // 4. Narrow rules for the values below the masking threshold.
        let mut out = apply_ranges(line, &ranges);
        for (key, value) in self.shorts.iter() {
            out = mask_token(&out, value);
            out = mask_keyed(&out, key, value);
        }
        out
    }

    /// The complete occurrences of the long values inside `line`.
    ///
    /// Every occurrence of every value is collected; the overlaps are merged
    /// when the ranges are applied. That matches the stateless [`mask_line`],
    /// which replaces *every* occurrence of a value: a value that overlaps
    /// itself is still a value.
    fn occurrences(&self, line: &str) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for secret in self.masks.iter() {
            // An empty value matches at every position and would mask the
            // whole line.
            if secret.is_empty() {
                continue;
            }
            ranges.extend(line.match_indices(secret.as_str()).map(|(pos, _)| (pos, secret.len())));
        }
        ranges.sort_unstable();
        ranges
    }

    /// The longest suffix of `line` that is a proper prefix of a long value.
    ///
    /// Returns the byte length of the prefix and the value it belongs to.
    fn tail_prefix(&self, line: &str) -> Option<(usize, String)> {
        if line.is_empty() {
            return None;
        }
        let bytes = line.as_bytes();
        let mut best: Option<(usize, usize)> = None;
        for (idx, secret) in self.masks.iter().enumerate() {
            let secret_bytes = secret.as_bytes();
            for &boundary in &self.boundaries[idx] {
                if boundary > bytes.len() {
                    continue;
                }
                // Cheap reject first: the suffix starts with the value's first
                // byte, so a mismatch there rules the length out in O(1).
                if bytes[bytes.len() - boundary] != secret_bytes[0] {
                    continue;
                }
                if bytes.ends_with(&secret_bytes[..boundary]) {
                    if best.is_none_or(|(best_len, _)| boundary > best_len) {
                        best = Some((boundary, idx));
                    }
                    break;
                }
            }
        }
        best.map(|(len, idx)| (len, self.masks[idx].clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use proptest::prelude::{prop_assert, prop_assert_eq};

    use super::{
        CAPTURE_SEPARATOR, MASK, SecretMasker, mask_keyed, mask_line, mask_token,
        parse_capture_records, parse_capture_records_checked, prepare_masks, render_env,
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
    fn checked_records_reject_a_leading_digit_name() {
        // `1BAD` is non-empty but not a valid variable name: the name check
        // is a disjunction, so either side alone must reject it.
        assert!(matches!(
            parse_capture_records_checked(b"1BAD=x\0", None),
            Err(crate::error::CaptureError::UnexpectedVar { .. })
        ));
    }

    #[test]
    fn checked_records_reject_an_empty_name() {
        assert!(matches!(
            parse_capture_records_checked(b"=x\0", None),
            Err(crate::error::CaptureError::UnexpectedVar { .. })
        ));
    }

    #[test]
    fn checked_records_accept_a_listed_name() {
        let allowed = ["A".to_string()];
        let parsed = parse_capture_records_checked(b"A=1\0", Some(&allowed)).expect("listed name");
        assert_eq!(parsed.get("A").map(String::as_str), Some("1"));
    }

    #[test]
    fn checked_records_reject_an_unlisted_name() {
        let allowed = ["A".to_string()];
        assert!(matches!(
            parse_capture_records_checked(b"B=1\0", Some(&allowed)),
            Err(crate::error::CaptureError::UnexpectedVar { .. })
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
        let out = render_env(&entries).expect("valid identifiers render");
        assert_eq!(out, "export KEY='value';\nexport SECRET='s3cr3t';\n");
    }

    #[test]
    fn renders_empty() {
        assert_eq!(render_env(&[]).expect("empty env renders"), "");
    }

    #[test]
    fn refuses_a_key_that_is_not_a_shell_identifier() {
        // The key is written verbatim into shell source that is streamed to a
        // remote host: a key like `A; id` would inject shell into the payload.
        let entries = vec![("A; id".to_string(), "value".to_string())];
        let err = render_env(&entries).expect_err("an invalid key must be refused");
        assert_eq!(
            err.to_string(),
            "environment variable name `A; id` is not a valid shell identifier"
        );
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
        assert!(prepare_masks(&secrets).is_empty(), "an empty value is not a mask");
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
    fn prepare_masks_is_order_independent_for_equal_lengths() {
        // Two secrets of the same length must land in the same order on every
        // run: the masker breaks ties by position in the set, so an unstable
        // order would make the redaction differ between two identical runs.
        let forward = vec!["bbbb".to_string(), "aaaa".to_string()];
        let backward = vec!["aaaa".to_string(), "bbbb".to_string()];
        assert_eq!(prepare_masks(&forward), prepare_masks(&backward));
        assert_eq!(prepare_masks(&forward), vec!["aaaa", "bbbb"]);
    }

    #[test]
    fn mask_is_stable_constant() {
        assert_eq!(MASK, "***");
    }

    #[test]
    fn mask_token_redacts_only_standalone_occurrences() {
        // The value stands alone: redacted.
        assert_eq!(mask_token("pin=12345", "12345"), "pin=***");
        assert_eq!(mask_token("export PIN='12345'", "12345"), "export PIN='***'");
        // The value is part of a longer word: left alone.
        assert_eq!(mask_token("order=123456", "12345"), "order=123456");
        assert_eq!(mask_token("id=12345abc", "12345"), "id=12345abc");
        assert_eq!(mask_token("abcdef", "abc"), "abcdef");
    }

    #[test]
    fn mask_keyed_redacts_the_key_anchored_forms() {
        assert_eq!(mask_keyed("PIN=12345", "PIN", "12345"), "PIN=***");
        assert_eq!(mask_keyed("PIN='12345'", "PIN", "12345"), "PIN=***");
        assert_eq!(mask_keyed("PIN=\"12345\"", "PIN", "12345"), "PIN=***");
        // The label may differ in case from the environment key.
        assert_eq!(mask_keyed("pin=12345", "PIN", "12345"), "pin=***");
        // A different identifier with the same value is left alone.
        assert_eq!(mask_keyed("OTHER=12345", "PIN", "12345"), "OTHER=12345");
    }

    #[test]
    fn secret_masker_redacts_a_secret_split_across_lines() {
        let mut masker = SecretMasker::new(
            Arc::new(prepare_masks(&["supersecret_token".to_string()])),
            Arc::new(Vec::new()),
        );
        // The value is split across two lines: neither fragment may survive.
        let first = masker.redact_line("token=supersecret_to");
        let second = masker.redact_line("ken");
        assert!(!first.contains("supersecret_to"), "prefix leaked: {first}");
        assert!(!second.contains("ken"), "suffix leaked: {second}");
        assert!(!format!("{first}{second}").contains("supersecret_token"));
    }

    #[test]
    fn secret_masker_redacts_a_secret_split_at_the_first_character() {
        let mut masker = SecretMasker::new(
            Arc::new(prepare_masks(&["supersecret_value".to_string()])),
            Arc::new(Vec::new()),
        );
        let first = masker.redact_line("s");
        let second = masker.redact_line("upersecret_value");
        // The first fragment is too short to redact in place (redacting every
        // line that ends in `s` would make the output unreadable), but the
        // continuation is redacted, so the value cannot be reassembled.
        assert!(!second.contains("upersecret_value"), "suffix leaked: {second}");
        assert!(!format!("{first}{second}").contains("supersecret_value"));
    }

    #[test]
    fn secret_masker_leaves_unrelated_lines_alone() {
        let mut masker = SecretMasker::new(
            Arc::new(prepare_masks(&["supersecret_value".to_string()])),
            Arc::new(Vec::new()),
        );
        assert_eq!(masker.redact_line("ordinary output"), "ordinary output");
        assert_eq!(masker.redact_line("ends with s"), "ends with s");
    }

    #[test]
    fn secret_masker_redacts_short_values_with_the_narrow_rules() {
        let mut masker = SecretMasker::new(
            Arc::new(Vec::new()),
            Arc::new(vec![("PIN".to_string(), "12345".to_string())]),
        );
        assert_eq!(masker.redact_line("pin=12345"), "pin=***");
        assert_eq!(masker.redact_line("order=123456"), "order=123456");
    }

    /// A masker over the given long values.
    fn masker(values: &[&str]) -> SecretMasker {
        let owned: Vec<String> = values.iter().map(|v| (*v).to_string()).collect();
        SecretMasker::new(Arc::new(prepare_masks(&owned)), Arc::new(Vec::new()))
    }

    #[test]
    fn redact_text_redacts_a_whole_value() {
        // `redact_text` is the stateless path (notes, previews, headers).
        let masker = masker(&["supersecret_value"]);
        assert_eq!(masker.redact_text("export TOKEN='supersecret_value'"), "export TOKEN='***'");
    }

    #[test]
    fn redact_text_leaves_unrelated_text_alone() {
        let masker = masker(&["supersecret_value"]);
        assert_eq!(masker.redact_text("nothing to see here"), "nothing to see here");
    }

    #[test]
    fn redact_text_applies_the_narrow_rules_to_short_values() {
        let masker = SecretMasker::new(
            Arc::new(Vec::new()),
            Arc::new(vec![("PIN".to_string(), "12345".to_string())]),
        );
        assert_eq!(masker.redact_text("pin=12345"), "pin=***");
        assert_eq!(masker.redact_text("order=123456"), "order=123456");
    }

    #[test]
    fn mask_keyed_ignores_an_empty_key_or_value() {
        // Neither an empty key nor an empty value can anchor a `KEY=value`
        // form, so neither may be treated as one.
        assert_eq!(mask_keyed("=secretvalue", "", "secretvalue"), "=secretvalue");
        assert_eq!(mask_keyed("KEY=", "KEY", ""), "KEY=");
    }

    #[test]
    fn mask_keyed_handles_a_multi_byte_character_before_the_key() {
        // The identifier boundary is a byte offset: a multi-byte character in
        // front of the key must not cut the identifier in half.
        assert_eq!(mask_keyed("€KEY=secretvalue", "KEY", "secretvalue"), "€KEY=***");
    }

    #[test]
    fn the_text_around_a_masked_secret_survives() {
        let mut masker = masker(&["secretvalue"]);
        assert_eq!(masker.redact_line("hello secretvalue world"), "hello *** world");
    }

    #[test]
    fn every_occurrence_in_a_line_is_masked() {
        let mut masker = masker(&["secretvalue"]);
        assert_eq!(masker.redact_line("secretvalue and secretvalue!"), "*** and ***!");
    }

    #[test]
    fn an_adjacent_tail_prefix_is_masked_with_the_occurrence() {
        // The line ends with a proper prefix of a second secret, starting
        // exactly where the first occurrence ends: the two ranges are
        // adjacent and must collapse into a single mask.
        let mut masker = masker(&["secretvalue", "abcdefgh"]);
        assert_eq!(masker.redact_line("secretvalueabcd"), "***");
    }

    #[test]
    fn a_tail_prefix_inside_an_occurrence_is_still_tracked() {
        // The prefix starts inside the range the occurrence already covers,
        // so the occurrence masks it — but the continuation must still be
        // tracked, or the rest of the value would survive on the next line.
        let mut masker = masker(&["abcdefgh", "xabcd"]);
        assert_eq!(masker.redact_line("xabcd"), "***");
        assert_eq!(masker.redact_line("efgh"), "***");
    }

    #[test]
    fn a_tail_prefix_starts_at_its_own_offset() {
        // The prefix is redacted where it starts, not somewhere else in the
        // line.
        let mut masker = masker(&["abcdefgh"]);
        assert_eq!(masker.redact_line("xxabcd"), "xx***");
    }

    #[test]
    fn an_empty_line_does_not_continue_a_pending_value() {
        // The pending prefix is still tracked, but an empty line carries no
        // continuation and must not be masked.
        let mut masker = masker(&["supersecret_value"]);
        assert_eq!(masker.redact_line("s"), "s");
        assert_eq!(masker.redact_line(""), "");
    }

    #[test]
    fn a_value_split_over_three_lines_is_fully_masked() {
        // Every fragment must be redacted: the value must not be
        // reassemblable from the output.
        let mut masker = masker(&["abcdefgh"]);
        assert_eq!(masker.redact_line("abcd"), "***");
        assert_eq!(masker.redact_line("ef"), "***");
        assert_eq!(masker.redact_line("gh"), "***");
    }

    #[test]
    fn a_value_split_at_a_line_end_is_fully_masked() {
        // The value ends exactly on the line boundary.
        let mut masker = masker(&["abcdefgh"]);
        assert_eq!(masker.redact_line("abcd"), "***");
        assert_eq!(masker.redact_line("efgh"), "***");
    }

    #[test]
    fn the_longest_tail_prefix_wins() {
        // Two secrets share a tail prefix; the longer match must be tracked,
        // or the continuation would be redacted against the wrong value.
        let mut masker = masker(&["abcdefgh", "bcdefgh"]);
        assert_eq!(masker.redact_line("xxbcdef"), "xx***");
    }

    #[test]
    fn a_line_that_ends_with_a_secret_is_masked_as_a_whole() {
        let mut masker = masker(&["secretvalue"]);
        assert_eq!(masker.redact_line("value=secretvalue"), "value=***");
    }

    #[test]
    fn an_empty_line_is_returned_unchanged() {
        let mut masker = masker(&["secretvalue"]);
        assert_eq!(masker.redact_line(""), "");
    }

    #[test]
    fn a_line_without_a_secret_is_returned_unchanged() {
        let mut masker = masker(&["secretvalue"]);
        assert_eq!(masker.redact_line("completely unrelated"), "completely unrelated");
    }

    #[test]
    fn the_longest_secret_wins_a_tie() {
        // Both secrets match at the same offset: the mask set is ordered
        // longest-first, so the longer one wins and the shorter one does not
        // leave the longer secret's tail exposed.
        let mut masker = masker(&["abc", "ab"]);
        assert_eq!(masker.redact_line("abc"), "***");
    }

    #[test]
    fn an_earlier_match_of_a_shorter_secret_is_not_preferred() {
        // The shorter secret matches earlier in the line, but the set is
        // ordered longest-first: the first match *in the set* wins, so the
        // longer secret is masked whole.
        let mut masker = masker(&["abc", "bc"]);
        assert_eq!(masker.redact_line("abc"), "***");
    }

    #[test]
    fn the_tail_prefix_tie_is_broken_deterministically() {
        // Two secrets share the prefix `abcd`. The mask set is ordered
        // longest-first and then by value, so the continuation is tracked
        // against the same secret on every run and on every host.
        let mut masker = masker(&["abcdefgh", "abcdefxy"]);
        assert_eq!(masker.redact_line("abcd"), "***");
        assert_eq!(masker.redact_line("efgh"), "***");
    }

    #[test]
    fn the_longest_matching_prefix_wins() {
        // Two secrets match the tail with different prefix lengths: `prefix`
        // matches four bytes, `efZ` matches two. The longer match must be
        // the one that is tracked, or the continuation is redacted against
        // the wrong secret and leaks.
        let mut masker = masker(&["prefix", "efZ"]);
        assert_eq!(masker.redact_line("zzpref"), "zz***");
        assert_eq!(masker.redact_line("ix"), "***");
    }

    #[test]
    fn a_continuation_that_breaks_is_dropped() {
        // The pending prefix does not continue into an unrelated line, so the
        // line is left alone.
        let mut masker = masker(&["supersecret_value"]);
        assert_eq!(masker.redact_line("s"), "s");
        assert_eq!(masker.redact_line("nothing alike"), "nothing alike");
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
            let rendered = render_env(&entries).expect("generated keys are valid identifiers");
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
