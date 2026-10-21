//! A small unified diff.
//!
//! The drift check compares a file in the repository with the file the
//! target actually runs. A hash answers *whether* they differ; a diff
//! answers *how* — and the "how" is what an operator needs to decide
//! whether the drift is a bug or an intended change.
//!
//! The implementation is a plain longest-common-subsequence diff. It is
//! meant for configuration files (units, templates, manifests), not for
//! source code: the table is quadratic in the line count, so a file beyond
//! [`MAX_CELLS`] lines is reported as different without a line-level diff
//! rather than spending minutes on it.

/// The largest LCS table the diff will build.
///
/// Beyond this the two texts are reported as different without hunks: a
/// quadratic table over a huge file is worse than no diff at all.
const MAX_CELLS: usize = 1_000_000;

/// How many unchanged lines are shown around each change.
const CONTEXT: usize = 3;

/// One line of the diff.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    /// The line is unchanged.
    Equal(String),
    /// The line is only in the old text.
    Delete(String),
    /// The line is only in the new text.
    Insert(String),
}

/// Produce a unified diff between two texts.
///
/// Returns an empty string when the texts are identical.
///
/// # Panics
///
/// Never panics; the input size only bounds the work done.
#[must_use]
pub(crate) fn unified_diff(old: &str, new: &str, old_name: &str, new_name: &str) -> String {
    if old == new {
        return String::new();
    }
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();

    let ops = diff_ops(&old_lines, &new_lines);
    let hunks = hunks(&ops);
    if hunks.is_empty() {
        // The texts differ but not line-by-line (a trailing newline, or a
        // difference past the LCS table cap): say so plainly.
        return format!("--- {old_name}\n+++ {new_name}\n@@ files differ @@\n");
    }

    let mut out = format!("--- {old_name}\n+++ {new_name}\n");
    for hunk in hunks {
        out.push_str(&hunk.header);
        out.push('\n');
        for line in &hunk.lines {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A group of changed lines with their surrounding context.
#[derive(Debug, Clone)]
struct Hunk {
    /// The `@@ -a,b +c,d @@` header.
    header: String,
    /// The rendered lines (` `, `-` and `+` prefixed).
    lines: Vec<String>,
}

/// Turn two line lists into a sequence of diff operations.
fn diff_ops(old: &[&str], new: &[&str]) -> Vec<Op> {
    let Some(table) = lcs_table(old, new) else {
        // Too large for a line-level diff: report the whole thing as changed.
        let mut ops = Vec::with_capacity(old.len() + new.len());
        ops.extend(old.iter().map(|l| Op::Delete((*l).to_string())));
        ops.extend(new.iter().map(|l| Op::Insert((*l).to_string())));
        return ops;
    };

    let mut ops = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < old.len() && j < new.len() {
        if old[i] == new[j] {
            ops.push(Op::Equal(old[i].to_string()));
            i += 1;
            j += 1;
        } else if table[(i + 1) * (new.len() + 1) + j] >= table[i * (new.len() + 1) + j + 1] {
            ops.push(Op::Delete(old[i].to_string()));
            i += 1;
        } else {
            ops.push(Op::Insert(new[j].to_string()));
            j += 1;
        }
    }
    while i < old.len() {
        ops.push(Op::Delete(old[i].to_string()));
        i += 1;
    }
    while j < new.len() {
        ops.push(Op::Insert(new[j].to_string()));
        j += 1;
    }
    ops
}

/// The LCS length table, or `None` when the input is too large.
///
/// `table[i * width + j]` is the length of the longest common subsequence
/// of `old[i..]` and `new[j..]`.
fn lcs_table(old: &[&str], new: &[&str]) -> Option<Vec<usize>> {
    let width = new.len() + 1;
    if old.len().saturating_mul(width) > MAX_CELLS {
        return None;
    }
    let mut table = vec![0usize; (old.len() + 1) * width];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            table[i * width + j] = if old[i] == new[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }
    Some(table)
}

/// Group the operations into hunks with context.
fn hunks(ops: &[Op]) -> Vec<Hunk> {
    let changed: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| !matches!(op, Op::Equal(_)))
        .map(|(idx, _)| idx)
        .collect();
    if changed.is_empty() {
        return Vec::new();
    }

    // Merge the changed positions into ranges that share context.
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for &idx in &changed {
        let start = idx.saturating_sub(CONTEXT);
        let end = (idx + CONTEXT).min(ops.len().saturating_sub(1));
        match ranges.last_mut() {
            Some(last) if start <= last.1 + 1 => last.1 = last.1.max(end),
            _ => ranges.push((start, end)),
        }
    }

    let mut out = Vec::new();
    let (mut old_line, mut new_line) = (1usize, 1usize);
    let mut cursor = 0usize;
    for (start, end) in ranges {
        // Advance the line counters over the untouched region.
        while cursor < start {
            match &ops[cursor] {
                Op::Equal(_) => {
                    old_line += 1;
                    new_line += 1;
                }
                Op::Delete(_) => old_line += 1,
                Op::Insert(_) => new_line += 1,
            }
            cursor += 1;
        }
        let old_start = old_line;
        let new_start = new_line;
        let mut lines = Vec::new();
        let mut old_count = 0usize;
        let mut new_count = 0usize;
        let mut idx = start;
        while idx <= end {
            match &ops[idx] {
                Op::Equal(text) => {
                    lines.push(format!(" {text}"));
                    old_count += 1;
                    new_count += 1;
                }
                Op::Delete(text) => {
                    lines.push(format!("-{text}"));
                    old_count += 1;
                }
                Op::Insert(text) => {
                    lines.push(format!("+{text}"));
                    new_count += 1;
                }
            }
            idx += 1;
        }
        cursor = end + 1;
        old_line += old_count;
        new_line += new_count;
        out.push(Hunk {
            header: format!("@@ -{old_start},{old_count} +{new_start},{new_count} @@"),
            lines,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::unified_diff;

    #[test]
    fn identical_texts_have_no_diff() {
        assert_eq!(unified_diff("a\nb\n", "a\nb\n", "old", "new"), "");
    }

    #[test]
    fn a_changed_line_is_shown() {
        let out = unified_diff("a\nb\nc\n", "a\nB\nc\n", "old", "new");
        assert!(out.contains("--- old"), "{out}");
        assert!(out.contains("+++ new"), "{out}");
        assert!(out.contains("-b"), "{out}");
        assert!(out.contains("+B"), "{out}");
        assert!(out.contains(" a"), "{out}");
    }

    #[test]
    fn an_added_line_is_shown() {
        let out = unified_diff("a\nc\n", "a\nb\nc\n", "old", "new");
        assert!(out.contains("+b"), "{out}");
        assert!(!out.contains("-a"), "{out}");
    }

    #[test]
    fn a_removed_line_is_shown() {
        let out = unified_diff("a\nb\nc\n", "a\nc\n", "old", "new");
        assert!(out.contains("-b"), "{out}");
    }

    #[test]
    fn unchanged_lines_around_a_change_are_kept_as_context() {
        let old = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        let new = "1\n2\n3\n4\nX\n6\n7\n8\n9\n10\n";
        let out = unified_diff(old, new, "old", "new");
        assert!(out.contains(" 3"), "{out}");
        assert!(out.contains(" 7"), "{out}");
        // The far ends are beyond the context window.
        assert!(!out.contains(" 1\n"), "{out}");
    }

    #[test]
    fn a_file_that_only_differs_in_its_last_line_is_reported() {
        let out = unified_diff("a\nb\n", "a\nc\n", "old", "new");
        assert!(out.contains("-b"), "{out}");
        assert!(out.contains("+c"), "{out}");
    }

    #[test]
    fn a_text_that_differs_only_by_a_trailing_newline_is_reported() {
        let out = unified_diff("a\n", "a", "old", "new");
        assert!(!out.is_empty());
    }

    #[test]
    fn an_empty_file_against_a_full_one_is_reported() {
        let out = unified_diff("", "a\n", "old", "new");
        assert!(out.contains("+a"), "{out}");
    }
}
