//! Placeholder extraction and rendering for credential templates (`${KEY}`).
//!
//! Target-side helpers (see `shellflow cred-env render`) substitute
//! `$CREDENTIALS_DIRECTORY/<KEY>` values into a template at unit start. This
//! module extracts the referenced keys (so tooling can cross-check a template
//! against an encrypted env file before deploying) and performs the literal
//! substitution itself.
//!
//! Only the braced form `${KEY}` is recognized, where `KEY` matches
//! `[A-Za-z_][A-Za-z0-9_]*` and is followed directly by `}`. Everything else
//! (including `$KEY` without braces and `${...}` with any other character) is
//! left to the template author — the braced form keeps substitution
//! unambiguous and value-safe.
//!
//! The scan is written with `str::find`/`match_indices` (never raw index
//! arithmetic on byte offsets) so no input can panic and every position the
//! scanner visits is covered by the tests below.

use std::{collections::HashMap, hash::BuildHasher};

/// A `${NAME}` placeholder occurrence in template text.
struct Placeholder {
    /// The referenced key (`NAME`).
    key: String,
    /// Byte offset of the `$` that opens the placeholder.
    start: usize,
    /// Byte offset just past the closing `}`.
    end: usize,
}

/// All `${NAME}` placeholder occurrences in `content`, in order.
///
/// Malformed forms are skipped (never matched), so a stray `${` costs one
/// extra scan iteration rather than an error.
fn placeholders(content: &str) -> Vec<Placeholder> {
    let mut out: Vec<Placeholder> = Vec::new();
    // Byte offset just past the last accepted placeholder; occurrences that
    // start before it are inside that placeholder's `${NAME}` text.
    let mut cursor = 0;
    for (rel, _) in content.match_indices("${") {
        if rel < cursor {
            continue;
        }
        let after = &content[rel + 2..];
        let name_len =
            after.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).unwrap_or(after.len());
        let (name, tail) = after.split_at(name_len);
        let is_name =
            !name.is_empty() && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_');
        if is_name && tail.starts_with('}') {
            // Advance past the closing brace. Note for mutation testing: a
            // cursor one byte smaller is an equivalent mutant — `${` cannot
            // begin inside the consumed `${NAME}` text, so no real match is
            // ever skipped by landing on the `}` itself.
            cursor = rel + 2 + name_len + 1;
            out.push(Placeholder { key: name.to_string(), start: rel, end: cursor });
        }
    }
    out
}

/// The credential keys referenced by `${KEY}` placeholders in `content`.
///
/// Keys are returned in first-seen order, de-duplicated. Repeated placeholders
/// for the same key collapse to one entry.
#[must_use]
pub fn template_keys(content: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for placeholder in placeholders(content) {
        if !keys.contains(&placeholder.key) {
            keys.push(placeholder.key);
        }
    }
    keys
}

/// Render `${KEY}` placeholders in `content` from `values`.
///
/// Substitution is **literal**: a value containing `&`, `|`, `$`, quotes or
/// backslashes is inserted verbatim (no `sed`-style replacement semantics),
/// and a value that itself contains `${...}` is never re-expanded — spans come
/// from the original text and are spliced left to right, so self-referential
/// values cannot loop.
///
/// # Errors
///
/// Returns the sorted list of keys the template references but `values` does
/// not provide. Callers must treat this as fatal (fail closed): nothing is
/// rendered, so a service never starts with a half-substituted config.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
///
/// use shellflow_core::render_template;
///
/// let mut values = HashMap::new();
/// values.insert("PASSWORD".to_string(), "a&b$c".to_string());
/// let rendered = render_template("password: \"${PASSWORD}\"", &values).expect("render");
/// assert_eq!(rendered, "password: \"a&b$c\"");
/// ```
pub fn render_template<S: BuildHasher>(
    content: &str,
    values: &HashMap<String, String, S>,
) -> Result<String, Vec<String>> {
    let spans = placeholders(content);

    let mut missing: Vec<String> = Vec::new();
    for placeholder in &spans {
        if !values.contains_key(&placeholder.key) && !missing.contains(&placeholder.key) {
            missing.push(placeholder.key.clone());
        }
    }
    if !missing.is_empty() {
        missing.sort();
        return Err(missing);
    }

    let mut out = String::with_capacity(content.len());
    let mut pos = 0;
    for placeholder in &spans {
        out.push_str(&content[pos..placeholder.start]);
        // Presence was verified above; `get` cannot fail here.
        if let Some(value) = values.get(&placeholder.key) {
            out.push_str(value);
        }
        pos = placeholder.end;
    }
    out.push_str(&content[pos..]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{render_template, template_keys};

    fn values(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
    }

    #[test]
    fn extracts_braced_keys_in_first_seen_order() {
        let keys = template_keys("a=${A} b=${B} c=${A}\n");
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn ignores_dollar_without_braces() {
        assert!(template_keys("cost is $5 and $A\n").is_empty(), "an unbraced `$` names nothing");
    }

    #[test]
    fn ignores_malformed_placeholders() {
        // No closing brace, invalid name, empty name, stray brace.
        assert!(template_keys("${A ${1BAD} ${} ${A{B}\n").is_empty(), "each form is malformed");
    }

    #[test]
    fn requires_name_start_with_letter_or_underscore() {
        let keys = template_keys("${_private} ${Z9} ${9Z}\n");
        assert_eq!(keys, vec!["_private", "Z9"]);
    }

    #[test]
    fn handles_adjacent_placeholders() {
        let keys = template_keys("${A}${B}${A}");
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn handles_dollar_before_valid_placeholder() {
        // The first `$` opens nothing; the second `${` opens the placeholder.
        let keys = template_keys("$${A}");
        assert_eq!(keys, vec!["A"]);
    }

    #[test]
    fn adjacent_dollar_between_placeholders() {
        // Kills an off-by-one in the cursor advance: skipping the second
        // placeholder would silently drop a key.
        let keys = template_keys("${A}$${B}");
        assert_eq!(keys, vec!["A", "B"]);
    }

    #[test]
    fn three_distinct_placeholders() {
        // Kills a cursor that advances too far (e.g. doubling the offset):
        // the third placeholder must still be seen.
        let keys = template_keys("${A}${B}${C}");
        assert_eq!(keys, vec!["A", "B", "C"]);
    }

    #[test]
    fn boundary_inputs_never_panic() {
        assert!(template_keys("").is_empty(), "an empty template has no keys");
        assert!(template_keys("no placeholders here").is_empty(), "plain text has no keys");
        assert!(template_keys("$").is_empty(), "a trailing lone dollar");
        assert!(template_keys("${").is_empty(), "unterminated opener");
        assert!(template_keys("${A").is_empty(), "missing closing brace");
        assert_eq!(template_keys("${A}"), vec!["A"], "placeholder at the very end");
        assert_eq!(template_keys("x${A}"), vec!["A"], "placeholder at the very end");
    }

    #[test]
    fn handles_multibyte_content() {
        // Non-ASCII bytes must not panic or split a char boundary.
        let keys = template_keys("🔑päss=${PASSWORD} tökén=${TOKEN}\n");
        assert_eq!(keys, vec!["PASSWORD", "TOKEN"]);
    }

    #[test]
    fn name_terminated_by_multibyte_char() {
        // A multi-byte char terminates the name scan without splitting it;
        // because the closing brace no longer immediately follows the name,
        // this is not a placeholder.
        assert!(
            template_keys("${KEYé}=x").is_empty(),
            "the multi-byte char breaks the placeholder"
        );
        // With the brace directly after the name, the multi-byte text that
        // follows is irrelevant.
        assert_eq!(template_keys("${KEY}é"), vec!["KEY"]);
    }

    #[test]
    fn render_substitutes_all_placeholders() {
        let rendered =
            render_template("a=${A} b=${B}", &values(&[("A", "1"), ("B", "two")])).expect("render");
        assert_eq!(rendered, "a=1 b=two");
    }

    #[test]
    fn render_repeats_collapse_to_the_same_value() {
        let rendered = render_template("${A}-${A}-${A}", &values(&[("A", "x")])).expect("render");
        assert_eq!(rendered, "x-x-x");
    }

    #[test]
    fn render_inserts_values_literally() {
        // `&`, `|`, `$`, quotes and backslashes must survive verbatim: the
        // bash `${line//needle/val}` form would expand `&` to the match.
        let rendered = render_template("password: \"${P}\"", &values(&[("P", "a&b|c$d\"e'f\\g")]))
            .expect("render");
        assert_eq!(rendered, "password: \"a&b|c$d\"e'f\\g\"");
    }

    #[test]
    fn render_does_not_re_expand_substituted_values() {
        // A value that itself looks like a placeholder must not be expanded
        // (no infinite loop, no second pass).
        let rendered =
            render_template("v=${A}", &values(&[("A", "${B}"), ("B", "should-not-appear")]))
                .expect("render");
        assert_eq!(rendered, "v=${B}");
    }

    #[test]
    fn render_empty_value_is_substituted() {
        let rendered = render_template("x=[${A}]", &values(&[("A", "")])).expect("render");
        assert_eq!(rendered, "x=[]");
    }

    #[test]
    fn render_reports_every_missing_key_sorted() {
        let err = render_template(
            "${Z} ${A} ${Z} ${M}",
            &values(&[("A", "present"), ("UNUSED", "extra")]),
        )
        .expect_err("missing keys");
        assert_eq!(err, vec!["M", "Z"], "missing keys are reported sorted");
    }

    #[test]
    fn render_missing_key_renders_nothing() {
        // Fail closed: no partial output is produced on error.
        let err = render_template("keep ${A} drop ${B}", &values(&[("A", "1")]))
            .expect_err("one missing key");
        assert_eq!(err, vec!["B"]);
    }

    #[test]
    fn render_leaves_malformed_placeholders_untouched() {
        let rendered = render_template("$A ${1BAD} ${}", &values(&[])).expect("render");
        assert_eq!(rendered, "$A ${1BAD} ${}");
    }

    #[test]
    fn render_multibyte_values_and_template() {
        let rendered =
            render_template("🔑päss=${P}", &values(&[("P", "väl🔒&$|")])).expect("render");
        assert_eq!(rendered, "🔑päss=väl🔒&$|");
    }

    proptest::proptest! {
        #[test]
        fn extracted_keys_are_valid_var_names(content in "\\PC*") {
            for key in template_keys(&content) {
                let mut chars = key.chars();
                match chars.next() {
                    Some(first) => {
                        proptest::prop_assert!(first.is_ascii_alphabetic() || first == '_');
                        proptest::prop_assert!(chars.all(|c| c.is_ascii_alphanumeric() || c == '_'));
                    }
                    None => proptest::prop_assert!(false, "extracted keys are never empty"),
                }
            }
        }

        #[test]
        fn every_referenced_key_is_found(content in "[A-Z_]{1,8}") {
            let text = format!("x=${{{content}}}");
            proptest::prop_assert_eq!(template_keys(&text), vec![content]);
        }

        #[test]
        fn never_panics_on_arbitrary_text(content in "\\PC*") {
            // The property is simply that the call returns.
            let _ = template_keys(&content);
        }

        #[test]
        fn render_succeeds_when_all_keys_present(
            names in proptest::collection::vec("[A-Z_]{1,8}", 1..6),
            vals in proptest::collection::vec("[a-z0-9]{0,8}", 1..6),
        ) {
            // Build a template referencing every generated name (deduplicated,
            // first-seen order) and a value map covering them.
            let mut keys: Vec<String> = Vec::new();
            for n in &names {
                if !keys.contains(n) { keys.push(n.clone()); }
            }
            let map: HashMap<String, String> = keys
                .iter()
                .enumerate()
                .map(|(i, k)| (k.clone(), vals[i % vals.len()].clone()))
                .collect();
            let mut template = String::new();
            for k in &keys {
                template.push_str(&format!("<${{{k}}}>"));
            }
            let rendered = render_template(&template, &map).expect("all keys present");
            let mut expected = String::new();
            for k in &keys {
                expected.push_str(&format!("<{}>", map[k.as_str()]));
            }
            proptest::prop_assert_eq!(rendered.as_str(), expected.as_str());
            // Values are plain words, so no placeholder survives rendering.
            proptest::prop_assert!(template_keys(&rendered).is_empty());
        }

        #[test]
        fn render_reports_exactly_the_missing_keys(
            names in proptest::collection::vec("[A-Z_]{1,8}", 1..6),
        ) {
            let mut keys: Vec<String> = Vec::new();
            for n in &names {
                if !keys.contains(n) { keys.push(n.clone()); }
            }
            let mut template = String::new();
            for k in &keys {
                template.push_str(&format!("${{{k}}}"));
            }
            let err = render_template(&template, &HashMap::new()).expect_err("no values");
            let mut expected = keys.clone();
            expected.sort();
            proptest::prop_assert_eq!(err, expected);
        }
    }
}
