//! Here-document aware line scanning.
//!
//! A deploy script is ordinary Bash, so it may legitimately contain a
//! here-document whose body is *data* — a systemd unit, a YAML manifest, a
//! template that happens to contain a `# @` comment. Such a line must stay
//! script content; interpreting it as a shellflow directive would silently
//! rewrite the user's block boundaries (or worse, redirect a block to a
//! different host).
//!
//! Detection is deliberately lexical, mirroring the parser's line scanner: a
//! small state machine tracks `<<TAG` / `<<-TAG` openers and consumes lines
//! verbatim until the matching terminator.
//!
//! # Known limitations
//!
//! - A delimiter that the shell expands (`<<$TAG`, `` <<`gen_tag` ``) is not statically knowable,
//!   so it is **not** tracked and its body keeps the legacy (untracked) behavior. Quoted
//!   (`<<'TAG'`, `<<"TAG"`) and backslash-escaped (`<<\TAG`) delimiters are literal and always
//!   tracked.
//! - Quoting is tracked per line. Bash re-parses command substitutions (`$(cat <<EOF … )`) with its
//!   own quote state, so a `#` or `<<` inside one may be classified against the outer line state.
//!   Statement-level here-documents — the overwhelmingly common case — are exact.

/// A here-document opened on some line and still waiting for its terminator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Heredoc {
    /// The literal delimiter that terminates the body.
    pub tag: String,
    /// `<<-`: the terminator line may be indented with tabs (Bash strips them).
    pub strip_tabs: bool,
}

impl Heredoc {
    /// Whether `line` terminates this here-document.
    ///
    /// For `<<-` only leading **tabs** are stripped, matching Bash: a
    /// terminator indented with spaces is not recognized and the body
    /// continues.
    #[must_use]
    pub fn terminates(&self, line: &str) -> bool {
        let candidate = if self.strip_tabs { line.trim_start_matches('\t') } else { line };
        candidate == self.tag
    }
}

/// Tracks here-documents opened by the lines seen so far.
///
/// Bodies are consumed in FIFO order because a single line may open several
/// here-documents (`cat <<A <<B`), whose bodies follow on consecutive lines.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeredocTracker {
    /// Open here-documents, in the order Bash consumes their bodies.
    open: Vec<Heredoc>,
}

impl HeredocTracker {
    /// Whether a here-document body is currently open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.open.is_empty()
    }

    /// Record every here-document opened by `line`.
    pub fn open_in(&mut self, line: &str) {
        self.open.extend(scan_openers(line));
    }

    /// Consume `line` as here-document body content.
    ///
    /// Returns `true` when a body was open — so the line is content, never a
    /// directive — and the terminator, if this line was one, has been
    /// consumed. Returns `false` when no body is open, in which case the line
    /// must be processed normally.
    pub fn consume_body(&mut self, line: &str) -> bool {
        let Some(head) = self.open.first() else {
            return false;
        };
        if head.terminates(line) {
            self.open.remove(0);
        }
        true
    }
}

/// Find every here-document opener on `line`, in source order.
///
/// `<<<` here-strings, quoted regions, and trailing comments are skipped, so
/// `echo 'a << b'`, `<<<"$x"`, and `# see <<EOF` open nothing.
#[must_use]
pub fn scan_openers(line: &str) -> Vec<Heredoc> {
    let bytes = line.as_bytes();
    let mut openers = Vec::new();
    let mut i = 0;
    // Bash starts a comment only where a `#` begins a word; tracking that
    // keeps `# see <<EOF` from opening a here-document.
    let mut word_start = true;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i = (i + 2).min(bytes.len());
                word_start = false;
            }
            quote @ (b'\'' | b'"') => {
                i = quote_end(bytes, i + 1, quote, quote == b'"');
                word_start = false;
            }
            b'#' if word_start => break,
            b'<' if bytes.get(i + 1) == Some(&b'<') => {
                if bytes.get(i + 2) == Some(&b'<') {
                    // `<<<` is a here-string: no body, no terminator.
                    i += 3;
                } else {
                    i += 2;
                    if let Some((heredoc, next)) = read_heredoc(bytes, i) {
                        openers.push(heredoc);
                        i = next;
                    }
                }
                word_start = true;
            }
            byte => {
                word_start = starts_word(byte);
                i += 1;
            }
        }
    }
    openers
}

/// Index just past the closing `quote`, or the line length when unterminated.
/// With `escapes`, a backslash consumes the byte that follows it.
fn quote_end(bytes: &[u8], mut start: usize, quote: u8, escapes: bool) -> usize {
    while start < bytes.len() {
        if escapes && bytes[start] == b'\\' {
            start = (start + 2).min(bytes.len());
            continue;
        }
        if bytes[start] == quote {
            return start + 1;
        }
        start += 1;
    }
    bytes.len()
}

/// Read the here-document that starts at `start` (just past `<<`).
///
/// Returns the opened document and the index just past its delimiter, or
/// `None` when the delimiter is absent or expanded by the shell.
fn read_heredoc(bytes: &[u8], mut start: usize) -> Option<(Heredoc, usize)> {
    let strip_tabs = bytes.get(start) == Some(&b'-');
    if strip_tabs {
        start += 1;
    }
    while matches!(bytes.get(start), Some(b' ' | b'\t')) {
        start += 1;
    }
    let (tag, next, literal) = read_tag(bytes, start)?;
    // An empty delimiter opens nothing, and an expanded one (`<<$TAG`) is
    // only knowable at run time, so neither can be tracked.
    if !literal || tag.is_empty() {
        return None;
    }
    Some((Heredoc { tag, strip_tabs }, next))
}

/// Read a here-document delimiter word starting at `start`.
///
/// Returns the delimiter text, the index just past it, and whether the
/// delimiter is fully literal (so its body can be tracked statically).
fn read_tag(bytes: &[u8], start: usize) -> Option<(String, usize, bool)> {
    // `<<'TAG'` / `<<"TAG"`: a quoted word. Single quotes suppress every
    // expansion; double quotes still allow `$` and `` ` ``, so the text is
    // inspected for them.
    if let Some(&quote @ (b'\'' | b'"')) = bytes.get(start) {
        let (body, next) = match closing_quote(bytes, start + 1, quote, quote == b'"') {
            Some(close) => (bytes[start + 1..close].to_vec(), close + 1),
            None => (bytes[start + 1..].to_vec(), bytes.len()),
        };
        let text = String::from_utf8_lossy(&body).into_owned();
        let literal = quote == b'\'' || !text.contains(['$', '`']);
        return Some((text, next, literal));
    }

    // A bare word: `\X` contributes `X` literally, while `$` and `` ` `` make
    // the delimiter dynamic.
    let mut raw: Vec<u8> = Vec::new();
    let mut i = start;
    let mut literal = true;
    while let Some(&byte) = bytes.get(i) {
        if is_tag_end(byte) {
            break;
        }
        if byte == b'\\' {
            match bytes.get(i + 1) {
                Some(&escaped) => {
                    raw.push(escaped);
                    i += 2;
                    continue;
                }
                None => break,
            }
        }
        if matches!(byte, b'$' | b'`') {
            literal = false;
        }
        raw.push(byte);
        i += 1;
    }
    Some((String::from_utf8_lossy(&raw).into_owned(), i, literal))
}

/// Index of the closing `quote` at or after `start`, or `None` when the line
/// ends before it. With `escapes`, a backslash consumes the byte after it.
fn closing_quote(bytes: &[u8], mut start: usize, quote: u8, escapes: bool) -> Option<usize> {
    while start < bytes.len() {
        if escapes && bytes[start] == b'\\' {
            start = (start + 2).min(bytes.len());
            continue;
        }
        if bytes[start] == quote {
            return Some(start);
        }
        start += 1;
    }
    None
}

/// Whether `byte` ends a bare here-document delimiter word.
const fn is_tag_end(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>')
}

/// Whether `byte` ends the current word for the purpose of comment detection.
const fn starts_word(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' | b'=')
}

#[cfg(test)]
mod tests {
    use proptest::sample::select;

    use super::{Heredoc, HeredocTracker, scan_openers};

    fn tags(line: &str) -> Vec<String> {
        scan_openers(line).into_iter().map(|heredoc| heredoc.tag).collect()
    }

    #[test]
    fn detects_plain_heredoc() {
        assert_eq!(
            scan_openers("cat <<EOF"),
            vec![Heredoc { tag: "EOF".to_string(), strip_tabs: false }]
        );
    }

    #[test]
    fn detects_quoted_delimiters() {
        assert_eq!(tags("cat <<'INNER'"), vec!["INNER"]);
        assert_eq!(tags("cat <<\"INNER\""), vec!["INNER"]);
        // `\E` contributes a literal `E`; the rest of the word follows.
        assert_eq!(tags("cat <<\\EOF"), vec!["EOF"]);
    }

    #[test]
    fn detects_indented_heredoc() {
        assert_eq!(
            scan_openers("cat <<-EOF"),
            vec![Heredoc { tag: "EOF".to_string(), strip_tabs: true }]
        );
    }

    #[test]
    fn skips_space_between_operator_and_tag() {
        assert_eq!(tags("cat << EOF"), vec!["EOF"]);
        assert_eq!(tags("cat <<\tEOF"), vec!["EOF"]);
    }

    #[test]
    fn tag_stops_at_redirection_and_separator() {
        assert_eq!(tags("cat <<EOF > out.txt"), vec!["EOF"]);
        assert_eq!(tags("cat <<EOF; echo done"), vec!["EOF"]);
        assert_eq!(tags("cat <<EOF|wc -c"), vec!["EOF"]);
        assert_eq!(tags("cat <<EOF#suffix"), vec!["EOF#suffix"]);
    }

    #[test]
    fn here_string_is_not_a_heredoc() {
        assert!(scan_openers("grep foo <<<\"$bar\"").is_empty());
    }

    #[test]
    fn quoted_region_is_not_scanned() {
        assert!(scan_openers("echo 'a << b'").is_empty());
        assert!(scan_openers("echo \"a << b\"").is_empty());
        // The quoted `<<` opens nothing; the real opener after it still does.
        assert_eq!(tags("echo '<<' <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn comment_does_not_open_a_heredoc() {
        assert!(scan_openers("# see <<EOF for details").is_empty());
        assert_eq!(tags("cat <<EOF # and <<OTHER"), vec!["EOF"]);
    }

    #[test]
    fn hash_inside_a_word_is_not_a_comment() {
        // Bash only starts a comment where `#` begins a word, so `a#b <<EOF`
        // still opens a here-document.
        assert_eq!(tags("echo a#b <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn backslash_escape_skips_the_next_byte() {
        // The escaped space must not be treated as the word boundary that
        // separates `<<` from its delimiter.
        assert_eq!(tags("echo a\\ <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn here_string_advances_past_all_three_angle_brackets() {
        // `<<<"x" <<EOF`: the here-string consumes `"x"`, and the real
        // delimiter after it is still found.
        assert_eq!(tags("grep <<<\"x\" <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn double_quotes_honor_backslash_escapes() {
        // `\"` does not close the string, so the `<<` after it stays inside it.
        assert!(scan_openers("echo \"x\\\" <<EOF\"").is_empty());
    }

    #[test]
    fn single_quoted_opener_is_inert_until_the_closing_quote() {
        // The `<<` inside the single-quoted region is inert, and the real
        // opener after the closing quote is still found.
        assert_eq!(tags("echo 'x << y' <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn multiple_openers_on_one_line_keep_order() {
        assert_eq!(tags("diff <(cat <<A) <(cat <<B)"), vec!["A", "B"]);
    }

    #[test]
    fn adjacent_openers_without_whitespace_are_both_found() {
        // Bash concatenates redirections, so `cat <<A<<B` really does open two
        // here-documents whose bodies follow in order.
        assert_eq!(tags("cat <<A<<B"), vec!["A", "B"]);
    }

    #[test]
    fn expanded_delimiter_is_not_tracked() {
        // `<<$TAG` cannot be resolved statically: no body is tracked.
        assert!(scan_openers("cat <<$TAG").is_empty());
        assert!(scan_openers("cat <<\"$TAG\"").is_empty());
        assert!(scan_openers("cat <<`gen_tag`").is_empty());
    }

    #[test]
    fn unterminated_quote_runs_to_the_end_of_the_line() {
        // Bash continues a quoted word onto the next line, so the scanner must
        // treat the rest of the line as the quoted region instead of indexing
        // past the end.
        assert!(scan_openers("echo \"unterminated").is_empty());
        assert!(scan_openers("echo 'unterminated").is_empty());
    }

    #[test]
    fn escaped_backslash_inside_double_quotes_is_consumed() {
        // `\\` is an escaped backslash, not an escaped quote, so the string
        // really does end and the trailing opener is outside it.
        assert_eq!(tags("echo \"a\\\\\" <<EOF"), vec!["EOF"]);
    }

    #[test]
    fn here_string_word_is_not_a_delimiter() {
        // `cat <<<EOF` is a here-string whose word is `EOF`; `cat <<EOF` opens
        // a body. Conflating the two would invent a here-document that Bash
        // never has.
        assert!(scan_openers("cat <<<EOF").is_empty());
        assert!(scan_openers("cat <<<'EOF'").is_empty());
    }

    #[test]
    fn four_angle_brackets_do_not_open_a_heredoc() {
        // `<<<<` is a shell syntax error, but the scanner must stay total: it
        // may not mistake the third `<` for a delimiter and must not loop.
        assert!(scan_openers("cat <<<<EOF").is_empty());
    }

    #[test]
    fn quoted_delimiter_honors_escaped_quotes() {
        // Inside `<<"…"` a `\"` is escaped, so the closing quote is further
        // along and the delimiter is the whole `E\"OF` word rather than the
        // truncated `\`. The tag is kept verbatim (no unescaping), which is
        // fine because Bash also compares it literally.
        assert_eq!(tags("cat <<\"E\\\"OF\""), vec!["E\\\"OF"]);
    }

    #[test]
    fn one_line_can_open_several_quoted_delimiters() {
        // The closing quote is consumed, so scanning resumes after it — and
        // `cat <<A <<B` really does open both here-documents in Bash.
        assert_eq!(tags("cat <<\"EOF\" <<DONE"), vec!["EOF", "DONE"]);
    }

    #[test]
    fn unterminated_quoted_delimiter_takes_the_rest_of_the_line() {
        // An unterminated `<<"` swallows the rest of the line as the
        // delimiter word, exactly as Bash continues the word.
        assert_eq!(tags("cat <<\"EOF"), vec!["EOF"]);
    }

    #[test]
    fn empty_delimiter_opens_nothing() {
        assert!(scan_openers("echo a <<").is_empty());
        assert!(scan_openers("echo a << ").is_empty());
        assert!(scan_openers("echo a <<>file").is_empty());
    }

    #[test]
    fn terminator_must_match_exactly() {
        let heredoc = Heredoc { tag: "EOF".to_string(), strip_tabs: false };
        assert!(heredoc.terminates("EOF"));
        assert!(!heredoc.terminates("EOFX"));
        assert!(!heredoc.terminates("EOF "));
        assert!(!heredoc.terminates("  EOF"));
    }

    #[test]
    fn indented_terminator_allows_only_tabs() {
        let heredoc = Heredoc { tag: "EOF".to_string(), strip_tabs: true };
        assert!(heredoc.terminates("\t\tEOF"));
        assert!(!heredoc.terminates("    EOF"));
    }

    #[test]
    fn tracker_consumes_body_until_terminator() {
        let mut tracker = HeredocTracker::default();
        assert!(!tracker.is_open());
        assert!(!tracker.consume_body("plain line"));

        tracker.open_in("cat <<EOF");
        assert!(tracker.is_open());
        assert!(tracker.consume_body("body line"));
        assert!(tracker.is_open());
        assert!(tracker.consume_body("# @remote web"));
        assert!(tracker.is_open());
        assert!(tracker.consume_body("EOF"));
        assert!(!tracker.is_open());
        assert!(!tracker.consume_body("after"));
    }

    #[test]
    fn tracker_drains_multiple_openers_in_order() {
        let mut tracker = HeredocTracker::default();
        tracker.open_in("diff <(cat <<A) <(cat <<B)");
        assert!(tracker.consume_body("first A"));
        assert!(tracker.is_open());
        assert!(tracker.consume_body("A"));
        assert!(tracker.is_open());
        assert!(tracker.consume_body("first B"));
        assert!(tracker.consume_body("B"));
        assert!(!tracker.is_open());
    }

    #[test]
    fn unterminated_heredoc_swallows_the_rest() {
        // Mirrors Bash: a here-document left open at end of file still
        // consumes every following line as body content.
        let mut tracker = HeredocTracker::default();
        tracker.open_in("cat <<EOF");
        assert!(tracker.consume_body("anything"));
        assert!(tracker.consume_body("at all"));
        assert!(tracker.is_open());
    }

    proptest::proptest! {
        /// A body line that differs from the delimiter never terminates the
        /// here-document, so unrelated content cannot end a body early.
        #[test]
        fn non_matching_line_never_terminates(
            tag in "[A-Z]{2,6}",
            line in select(vec!["EOF", "EOFX", " EOF", "body", "", "# @remote web", "EO\tF"]),
        ) {
            let heredoc = Heredoc { tag: tag.clone(), strip_tabs: false };
            proptest::prop_assume!(line != tag);
            proptest::prop_assert!(!heredoc.terminates(&line));
        }

        /// Every delimiter the scanner reports can actually be found, and the
        /// body is consumed until that exact line.
        #[test]
        fn scanned_opener_terminates_at_its_tag(
            tag in "[A-Z]{2,6}",
            body in select(vec!["", "body", "# @remote web", "EOFX"]),
        ) {
            let mut tracker = HeredocTracker::default();
            tracker.open_in(&format!("cat <<{tag}"));
            proptest::prop_assert!(tracker.is_open());
            proptest::prop_assert!(tracker.consume_body(&body));
            proptest::prop_assert!(tracker.is_open());
            proptest::prop_assert!(tracker.consume_body(&tag));
            proptest::prop_assert!(!tracker.is_open());
        }
    }
}
