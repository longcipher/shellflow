//! Parsing of `KEY=VALUE` environment files (the plaintext form of an
//! encrypted `.env.age` file).

use crate::error::SecretsError;

/// Strip one layer of surrounding `"` or `'` quotes.
///
/// The rule lives in `shellflow-text` so the parser and this crate share one
/// definition.
fn strip_quotes(value: &str) -> String {
    shellflow_text::strip_surrounding_quotes(value)
}

/// Parse an env file into ordered `(key, value)` pairs.
///
/// Blank lines and full-line `#` comments are ignored (inline `#` stays part
/// of the value). An optional single-space `export ` prefix per line is
/// tolerated; other whitespace forms (`export\tA=1`) are rejected as
/// malformed so a tab is never silently folded into a key. The first `=`
/// splits the key from the value; a surrounding pair of matching quotes is
/// stripped once from the value. Unquoted surrounding whitespace is trimmed
/// (quote to preserve it); no backslash escapes are processed, unlike bash
/// double quotes.
///
/// A repeated key keeps the **last** value and appears once, in the position
/// of its first occurrence — matching bash `source` semantics and keeping the
/// key list (`LT_SECRET_KEYS`, `secret creds`, `secret keys-check`) free of
/// phantom duplicates.
///
/// # Errors
///
/// Returns [`SecretsError::MalformedEnv`] when a line has no `=`, has an
/// invalid variable name, or an `export` line has no assignment.
pub fn parse_env_file(content: &str) -> Result<Vec<(String, String)>, SecretsError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let assignment = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, value)) = assignment.split_once('=') else {
            return Err(SecretsError::MalformedEnv {
                line: idx + 1,
                reason: "expected `KEY=VALUE`".to_string(),
            });
        };

        let key = key.trim();
        if !shellflow_text::is_valid_var_name(key) {
            return Err(SecretsError::MalformedEnv {
                line: idx + 1,
                reason: format!("invalid variable name `{key}`"),
            });
        }
        let value = strip_quotes(value);
        match out.iter_mut().find(|(k, _)| k == key) {
            // Later assignment wins; the key keeps its original position.
            Some(slot) => slot.1 = value,
            None => out.push((key.to_string(), value)),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_key_keeps_the_last_value_once() {
        // `source` semantics: the last assignment wins and the key appears
        // once, so `secret creds` / `keys-check` see no phantom duplicates.
        let parsed = parse_env_file("A=1\nB=2\nA=3\n").expect("parse");
        assert_eq!(
            parsed,
            vec![("A".to_string(), "3".to_string()), ("B".to_string(), "2".to_string())]
        );
    }

    #[test]
    fn parses_basic_pairs() {
        let pairs = parse_env_file("A=1\nB=two\n").expect("parse");
        assert_eq!(
            pairs,
            vec![("A".to_string(), "1".to_string()), ("B".to_string(), "two".to_string())]
        );
    }

    #[test]
    fn ignores_comments_and_blanks() {
        let pairs = parse_env_file("# comment\n\nA=1\n  \n# another\nB=2\n").expect("parse");
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn value_may_contain_equals_and_quotes() {
        let pairs = parse_env_file("URL=https://x?q=a=b\nTOKEN=\"a b\"\n").expect("parse");
        assert_eq!(pairs[0].1, "https://x?q=a=b");
        assert_eq!(pairs[1].1, "a b");
    }

    #[test]
    fn strips_surrounding_quotes() {
        let pairs = parse_env_file("A=\"v1\"\nB='v2'\n").expect("parse");
        assert_eq!(pairs[0].1, "v1");
        assert_eq!(pairs[1].1, "v2");
    }

    #[test]
    fn tolerates_export_prefix_and_crlf() {
        let pairs = parse_env_file("export A=1\r\nexport B=2\r\n").expect("parse");
        assert_eq!(pairs.len(), 2);
    }

    #[test]
    fn trims_whitespace_around_key() {
        let pairs = parse_env_file("  A  = 1 \n").expect("parse");
        assert_eq!(pairs[0].0, "A");
        assert_eq!(pairs[0].1, "1");
    }

    #[test]
    fn missing_equals_is_error() {
        let err = parse_env_file("A\n").expect_err("no equals");
        match err {
            SecretsError::MalformedEnv { line, reason } => {
                assert_eq!(line, 1, "line numbers are 1-based");
                assert!(reason.contains("KEY=VALUE"), "unexpected reason: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_key_is_error_with_line() {
        let err = parse_env_file("OK=1\n1BAD=1\n").expect_err("bad key");
        match err {
            SecretsError::MalformedEnv { line, reason } => {
                assert_eq!(line, 2, "line numbers are 1-based");
                assert!(reason.contains("1BAD"), "unexpected reason: {reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn empty_input_yields_empty() {
        assert!(parse_env_file("").expect("parse").is_empty());
        assert!(parse_env_file("\n\n# x\n").expect("parse").is_empty());
    }

    proptest::proptest! {
        #[test]
        fn parse_round_trips_simple_values(
            key in "[A-Z][A-Z0-9_]{0,24}",
            value in "[a-zA-Z0-9_./:+-]{0,64}",
        ) {
            let content = format!("{key}={value}\n");
            let pairs = parse_env_file(&content)
                .map_err(|e| proptest::prelude::TestCaseError::fail(e.to_string()))?;
            proptest::prop_assert_eq!(pairs, vec![(key, value)]);
        }
    }
}
