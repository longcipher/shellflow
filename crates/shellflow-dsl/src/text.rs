//! The two text rules the grammar and the runtime share.
//!
//! Both rules are about *shell text*: how a value is quoted, and how a
//! layer of surrounding quotes is removed. They live in one place because
//! the DSL (which reads a directive payload) and the runtime (which renders
//! a payload header) must agree on them — a disagreement shows up as a
//! broken payload, not as an error.

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

#[cfg(test)]
mod tests {
    use super::{shell_quote_single, strip_surrounding_quotes};

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
}
