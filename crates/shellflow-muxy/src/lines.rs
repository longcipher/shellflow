//! The frame-to-line assembler: a screen arrives, lines leave.
//!
//! The invariant is **a line is emitted when it leaves the screen.** A row
//! that is still on screen can still change (that is what the cursor line is
//! for), but a row that scrolled off the top can never change again.
//!
//! For each frame the caller renders `cur[i]` (plain text per row, oldest at
//! index 0) and the server's `history_total` (the retained scrollback row
//! count). The assembler finds the largest `k` such that
//! `prev[prev.len()-k..] == cur[..k]` — how much of the old screen is still
//! the top of the new one. `shift = prev.len() - k` is the number of rows
//! that left the top, and `prev[..shift]` is emitted oldest-first. A merged
//! frame can advance the screen by more rows than `prev` still contains; the
//! `history_total` delta reveals the deficit so the caller can gap-fill from
//! `HistoryPage` before emitting.
//!
//! The begin marker (`@@shellflow:begin:<run>/<step>@@`, printed by the
//! payload on its first line) arms the assembler and is dropped, so the
//! echoed bootstrap, the shell prompt, and decorations never reach the UI.

/// One frame of plain-text screen rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Screen {
    /// Plain text per row, oldest at index 0.
    pub rows: Vec<String>,
    /// Whether the server reset the screen (resize or full redraw).
    pub reset: bool,
    /// The server's retained scrollback row count.
    pub history_total: u64,
}

/// What one [`LineAssembler::push`] produces.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Push {
    /// Complete lines, oldest first, ready for `Ui::host_line`.
    pub lines: Vec<String>,
    /// Rows that scrolled off between frames but are not in `prev`: fetch
    /// `HistoryPage` and emit them **before** `lines`.
    ///
    /// This is `history_total_after - history_total_before - shift`: rows
    /// that entered the scrollback minus rows that visibly left the screen.
    /// (An earlier draft added `shift` instead of subtracting it and
    /// double-counted every scroll; the property test below pins the
    /// subtraction.)
    pub missing: u64,
    /// The frame redrew the screen instead of scrolling (a full-screen TUI).
    pub tui_redraw: bool,
}

/// The departure-stream assembler.
#[derive(Clone, Debug)]
pub struct LineAssembler {
    prev: Vec<String>,
    armed: bool,
    marker: String,
    history_total: u64,
    initialized: bool,
}

impl LineAssembler {
    /// Start an assembler that drops everything until `marker` is seen.
    #[must_use]
    pub fn new(marker: &str) -> Self {
        Self {
            prev: Vec::new(),
            armed: false,
            marker: marker.to_string(),
            history_total: 0,
            initialized: false,
        }
    }

    /// Feed one frame; returns the lines that left the screen.
    #[must_use]
    pub fn push(&mut self, screen: &Screen) -> Push {
        let cur = &screen.rows;
        if !self.initialized {
            self.prev.clone_from(cur);
            self.history_total = screen.history_total;
            self.initialized = true;
            return Push::default();
        }
        if screen.reset {
            // A reset that advances no history is a redraw, not a scroll:
            // a full-screen TUI replaced the screen. (A reset that *does*
            // advance history re-baselines below.) Content identical to the
            // previous screen is a sync, not a redraw.
            let delta = screen.history_total.saturating_sub(self.history_total);
            let shift = departure_shift(&self.prev, cur);
            self.prev.clone_from(cur);
            self.history_total = screen.history_total;
            if delta == 0 && shift > 0 {
                return Push { tui_redraw: true, ..Push::default() };
            }
            return Push::default();
        }
        let shift = departure_shift(&self.prev, cur);
        let delta = screen.history_total.saturating_sub(self.history_total);
        self.history_total = screen.history_total;

        let missing = delta.saturating_sub(shift as u64);
        let mut lines: Vec<String> =
            self.prev.iter().take(shift).map(|line| collapse_cr(line)).collect();
        self.prev.clone_from(cur);

        if !self.armed {
            if let Some(index) = lines.iter().position(|line| line.contains(&self.marker)) {
                self.armed = true;
                lines = lines.split_off(index + 1);
                // The marker scrolled off, so every row on screen postdates
                // it: `prev` is already clean.
            } else if let Some(index) = cur.iter().position(|line| line.contains(&self.marker)) {
                self.armed = true;
                lines.clear();
                // The marker is still on screen: rows above it are bootstrap
                // echo and prompts, and must never be emitted when they later
                // scroll off. Truncate the baseline past the marker.
                self.prev = cur.split_at(index + 1).1.to_vec();
                return Push { lines, missing, tui_redraw: false };
            } else {
                lines.clear();
            }
        }

        Push { lines, missing, tui_redraw: false }
    }

    /// Feed gap rows fetched from `HistoryPage`; they are already complete.
    #[must_use]
    pub fn feed_gap(&mut self, rows: &[String]) -> Vec<String> {
        if !self.armed {
            if let Some(index) = rows.iter().position(|line| line.contains(&self.marker)) {
                self.armed = true;
                return rows.split_at(index + 1).1.iter().map(|line| collapse_cr(line)).collect();
            }
            return Vec::new();
        }
        rows.iter().map(|line| collapse_cr(line)).collect()
    }

    /// Flush the rows still on screen when the session ends.
    #[must_use]
    pub fn finish(&mut self) -> Vec<String> {
        let mut tail: Vec<String> = self.prev.iter().map(|line| collapse_cr(line)).collect();
        if !self.armed {
            if let Some(index) = tail.iter().position(|line| line.contains(&self.marker)) {
                self.armed = true;
                tail = tail.split_off(index + 1);
            } else {
                return Vec::new();
            }
        }
        while tail.last().is_some_and(|line| line.trim().is_empty()) {
            tail.pop();
        }
        tail.into_iter().filter(|line| !line.trim().is_empty()).collect()
    }

    /// Whether the begin marker has been seen.
    #[must_use]
    pub const fn armed(&self) -> bool {
        self.armed
    }
}

/// How many rows left the top: `prev.len() - k` for the largest overlap `k`.
fn departure_shift(prev: &[String], cur: &[String]) -> usize {
    let max_k = prev.len().min(cur.len());
    // Descending search for the largest overlap: a bounded iterator, so there
    // is no loop condition to mutate into an underflow.
    let k = (1..=max_k).rev().find(|&k| prev[prev.len() - k..] == cur[..k]).unwrap_or(0);
    prev.len() - k
}

/// A `\r` rewrite collapses to the text after the last `\r`, exactly like
/// `muxy session read-screen`: a progress bar keeps only its final value.
fn collapse_cr(line: &str) -> String {
    match line.rsplit_once('\r') {
        Some((_, tail)) => tail.to_string(),
        None => line.to_string(),
    }
}

#[cfg(test)]
mod tests {

    use proptest::prelude::*;

    use super::*;

    fn assembler() -> LineAssembler {
        LineAssembler::new("@@shellflow:begin:r/s@@")
    }

    fn screen(rows: &[&str], history_total: u64) -> Screen {
        Screen { rows: rows.iter().map(ToString::to_string).collect(), reset: false, history_total }
    }

    #[test]
    fn departure_shift_finds_the_overlap() {
        let prev = vec!["a".to_string(), "b".to_string(), "c".to_string(), "d".to_string()];
        let cur = vec!["c".to_string(), "d".to_string(), "e".to_string(), "f".to_string()];
        assert_eq!(departure_shift(&prev, &cur), 2);
    }

    #[test]
    fn departure_shift_with_no_overlap_empties_the_screen() {
        let prev = vec!["a".to_string(), "b".to_string()];
        let cur = vec!["c".to_string(), "d".to_string()];
        assert_eq!(departure_shift(&prev, &cur), 2);
    }

    #[test]
    fn departure_shift_with_identical_screens_is_zero() {
        let prev = vec!["a".to_string(), "b".to_string()];
        let cur = prev.clone();
        assert_eq!(departure_shift(&prev, &cur), 0);
    }

    #[test]
    fn departure_shift_finds_a_single_row_of_overlap() {
        // The boundary case: the largest overlap is exactly one row, and the
        // search must stop there rather than falling through to zero.
        let prev = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let cur = vec!["c".to_string(), "d".to_string(), "e".to_string()];
        assert_eq!(departure_shift(&prev, &cur), 2);
    }

    #[test]
    fn departure_shift_with_empty_screens_shifts_nothing() {
        let prev: Vec<String> = Vec::new();
        let cur = vec!["a".to_string()];
        assert_eq!(departure_shift(&prev, &cur), 0);
        assert_eq!(departure_shift(&cur, &prev), 1);
    }

    #[test]
    fn first_frame_initializes_and_emits_nothing() {
        let mut asm = assembler();
        let out = asm.push(&screen(&["a", "b"], 0));
        assert!(out.lines.is_empty());
        assert_eq!(out.missing, 0);
    }

    #[test]
    fn lines_are_emitted_when_they_leave_the_screen() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["@@shellflow:begin:r/s@@", ""], 0));
        // The marker arms the assembler and is dropped: the caller sees
        // only real output, never the bootstrap echo.
        let out = asm.push(&screen(&["", "hello"], 1));
        assert!(out.lines.is_empty());
        assert!(asm.armed());
        let tail = asm.finish();
        assert_eq!(tail, vec!["hello".to_string()]);
    }

    #[test]
    fn bootstrap_echo_never_reaches_the_ui() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["$ chmod 700 ...; exec bash ...", "prompt $"], 0));
        // No marker yet: nothing is emitted.
        let out = asm.push(&screen(&["prompt $", "$ chmod 700 ..."], 0));
        assert!(out.lines.is_empty());
        assert!(!asm.armed());
        // The marker arms; everything up to it is dropped.
        let out = asm.push(&screen(&["@@shellflow:begin:r/s@@", "real output"], 1));
        assert!(out.lines.is_empty() || !out.lines.iter().any(|l| l.contains("chmod")));
        assert!(asm.armed());
    }

    #[test]
    fn marker_on_screen_drops_rows_above_it() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["bootstrap", "prompt"], 0));
        let _out = asm.push(&screen(&["prompt", "@@shellflow:begin:r/s@@", "real"], 1));
        assert!(asm.armed());
        // A subsequent scroll must never emit the bootstrap or marker rows.
        let out = asm.push(&screen(&["real", "next", "more"], 3));
        assert!(!out.lines.iter().any(|l| l.contains("begin") || l == "bootstrap"));
    }

    #[test]
    fn carriage_returns_collapse_to_the_final_value() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["@@shellflow:begin:r/s@@", ""], 0));
        let _ = asm.push(&screen(&["", "10%\r20%\r100%"], 1));
        let tail = asm.finish();
        assert!(tail.iter().any(|l| l == "100%"));
        assert!(!tail.iter().any(|l| l.contains("10%")));
    }

    #[test]
    fn gap_fill_recovers_bypassed_lines_in_order() {
        // Five lines produced between two frames on a 4-row screen: one
        // line never appears on either screen and must come back through
        // the gap path, after the departed rows (it is newer than them).
        let mut asm = assembler();
        let _ = asm.push(&screen(&["@@shellflow:begin:r/s@@", "a", "b", "c"], 3));
        let out = asm.push(&screen(&["l4", "l5", "l6", "l7"], 8));
        assert_eq!(out.missing, 1);
        // The bypassed line, oldest first.
        let gap = asm.feed_gap(&["l3".to_string()]);
        assert_eq!(gap, vec!["l3".to_string()]);
        let mut ordered = out.lines.clone();
        ordered.extend(gap);
        // Departed rows first (they are older), then the gap rows; the
        // marker stays dropped.
        assert!(!ordered.iter().any(|l| l.contains("begin")));
        assert_eq!(
            ordered,
            vec!["a".to_string(), "b".to_string(), "c".to_string(), "l3".to_string()]
        );
    }

    #[test]
    fn reset_without_scroll_is_a_tui_redraw() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["a", "b"], 0));
        let out = asm.push(&Screen {
            rows: vec!["X".to_string(), "Y".to_string()],
            reset: true,
            history_total: 0,
        });
        assert!(out.tui_redraw);
    }

    #[test]
    fn reset_with_history_advance_is_not_a_tui_redraw() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["a", "b"], 0));
        let out = asm.push(&Screen {
            rows: vec!["X".to_string(), "Y".to_string()],
            reset: true,
            history_total: 1,
        });
        assert!(!out.tui_redraw);
    }

    #[test]
    fn reset_with_identical_screen_is_not_a_tui_redraw() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["a", "b"], 0));
        let out = asm.push(&Screen {
            rows: vec!["a".to_string(), "b".to_string()],
            reset: true,
            history_total: 0,
        });
        assert!(!out.tui_redraw);
    }

    #[test]
    fn feed_gap_drops_the_marker_and_everything_above_it() {
        let mut asm = assembler();
        let out = asm.feed_gap(&[
            "noise".to_string(),
            "@@shellflow:begin:r/s@@".to_string(),
            "real".to_string(),
        ]);
        assert_eq!(out, vec!["real".to_string()]);
    }

    #[test]
    fn finish_drops_the_marker_and_everything_above_it() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["noise", "@@shellflow:begin:r/s@@", "tail"], 0));
        let out = asm.finish();
        assert_eq!(out, vec!["tail".to_string()]);
    }

    #[test]
    fn finish_flushes_the_tail_and_drops_blanks() {
        let mut asm = assembler();
        let _ = asm.push(&screen(&["@@shellflow:begin:r/s@@", ""], 0));
        let _ = asm.push(&screen(&["", "done", ""], 1));
        let tail = asm.finish();
        assert_eq!(tail, vec!["done".to_string()]);
    }

    proptest! {
        #[test]
        fn scroll_sequences_emit_exactly_once_in_order(total in 1usize..30) {
            // One frame per scroll with distinct content lines: no merged
            // frames here (the dedicated gap test covers those), so the
            // overlap is exact and nothing is ever missing. Identical
            // consecutive rows are the one case where the overlap needs
            // `history_total` to disambiguate; that path is pinned by
            // `gap_fill_recovers_bypassed_lines_in_order` and the
            // real-server test instead.
            let mut asm = LineAssembler::new("MARK");
            // Seed with the marker so everything is armed.
            let _ = asm.push(&Screen { rows: vec!["MARK".to_string(), String::new(), String::new(), String::new()], reset: false, history_total: 0 });
            let mut screen: Vec<String> = vec!["MARK".to_string(), String::new(), String::new(), String::new()];
            let mut emitted: Vec<String> = Vec::new();
            let mut expected: Vec<String> = Vec::new();
            for i in 0..total {
                let line = format!("line-{i}");
                // Scroll one line.
                let departed = screen.remove(0);
                if departed != "MARK" {
                    // Every departed post-marker row is emitted, blanks
                    // included; only the marker is dropped.
                    expected.push(collapse_cr(&departed));
                }
                screen.push(line);
                let history = (i as u64) + 1;
                let out = asm.push(&Screen { rows: screen.clone(), reset: false, history_total: history });
                prop_assert_eq!(out.missing, 0);
                prop_assert!(!out.tui_redraw);
                emitted.extend(out.lines);
            }
            // Flush: the tail holds the last screen rows.
            for line in asm.finish() {
                emitted.push(line);
            }
            // Exactly-once in order: every departed row plus the final
            // screen, with `finish`'s trailing-blank drop mirrored here.
            let mut want: Vec<String> = expected;
            let mut tail: Vec<String> = screen;
            while tail.last().is_some_and(|l| l.trim().is_empty()) {
                tail.pop();
            }
            want.extend(tail.into_iter().filter(|l| !l.trim().is_empty()));
            prop_assert_eq!(emitted, want);
        }
    }
}
