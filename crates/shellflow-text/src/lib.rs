//! The shell-text rules the DSL, the runtime, and the secrets crate share.
//!
//! Three rules travel together because every producer and consumer of shell
//! text must agree on them — a disagreement shows up as a broken payload or a
//! wrongly-rejected key, not as an error:
//!
//! * [`shell_quote_single`] — single-quote a value for a `bash` export line.
//! * [`strip_surrounding_quotes`] — remove one layer of literal quotes from a plain-text value (a
//!   directive payload, an env-file value).
//! * [`is_valid_var_name`] — the single definition of a shell identifier.
//!
//! The crate has no dependencies: it is the leaf of the workspace graph, so
//! the secrets crate can depend on it without dragging in the plan model.

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

/// Strip one layer of surrounding `"` or `'` quotes.
///
/// A directive or an env-file line is plain text, so no shell quoting applies
/// and quotes are literal characters; stripping them lets `--exclude '*.key'`
/// and `KEY="value"` read naturally.
///
/// This is the single definition of the rule across the workspace: the parser
/// uses it for directive payloads and the secrets crate uses it for the values
/// of a sealed env file.
#[must_use]
pub fn strip_surrounding_quotes(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if first == last && (first == b'"' || first == b'\'') {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

/// True for `[A-Za-z_][A-Za-z0-9_]*`.
///
/// This is the single definition of a shell identifier across the workspace:
/// the parser validates `@env`/`@export` names with it, the payload renderer
/// refuses to emit an `export` statement for anything else, and the secrets
/// crate reuses it for the keys of a sealed env file.
#[must_use]
pub fn is_valid_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::{is_valid_var_name, shell_quote_single, strip_surrounding_quotes};

    #[test]
    fn a_quoted_value_is_wrapped_in_single_quotes() {
        let quoted = shell_quote_single("hello");
        assert!(quoted.starts_with('\''), "{quoted}");
        assert!(quoted.ends_with('\''), "{quoted}");
        assert!(quoted.contains("hello"), "{quoted}");
    }

    #[test]
    fn a_quote_inside_the_value_is_escaped() {
        let quoted = shell_quote_single("it's");
        assert_eq!(quoted, "'it'\\''s'");
    }

    #[test]
    fn an_empty_value_still_produces_a_quoted_pair() {
        let quoted = shell_quote_single("");
        assert_eq!(quoted, "''");
    }

    #[test]
    fn one_layer_of_surrounding_quotes_is_removed() {
        assert_eq!(strip_surrounding_quotes("\"x\""), "x");
        assert_eq!(strip_surrounding_quotes("'x'"), "x");
        assert_eq!(strip_surrounding_quotes("x"), "x");
        assert_eq!(strip_surrounding_quotes("''"), "");
        assert_eq!(strip_surrounding_quotes("\""), "\"");
    }

    #[test]
    fn mismatched_quote_characters_are_never_stripped() {
        // The pair must be *the same* character: stripping an unmatched pair
        // would silently eat a literal quote the author meant to keep.
        assert_eq!(strip_surrounding_quotes("'x\""), "'x\"");
        assert_eq!(strip_surrounding_quotes("\"x'"), "\"x'");
        assert_eq!(strip_surrounding_quotes("'\"'"), "\"");
        assert_eq!(strip_surrounding_quotes("--exclude '*.key'"), "--exclude '*.key'");
    }

    #[test]
    fn a_shell_identifier_starts_with_a_letter_or_underscore() {
        assert!(is_valid_var_name("A"));
        assert!(is_valid_var_name("_private"));
        assert!(is_valid_var_name("Z9_more"));
        assert!(!is_valid_var_name(""));
        assert!(!is_valid_var_name("9BAD"));
        assert!(!is_valid_var_name("has-dash"));
        assert!(!is_valid_var_name("has.dot"));
    }
}
