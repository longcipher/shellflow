//! The `@image` step: pull container images and report digest drift.
//!
//! Pulls each image, compares the digest before and after, and reports which
//! images actually moved — the pull/compare/prune loop every container fleet
//! hand-writes, owned by the runner instead. The runtime is detected on the
//! target (`podman` first, then `docker`).

use crate::executor::quote;

/// The remote command for `@image`.
pub(super) fn image_command(images: &[String], prune: bool) -> String {
    let list: Vec<String> = images.iter().map(|i| quote(i)).collect();
    let prune_step = if prune {
        "echo 'pruning dangling images'; $RT image prune -f 2>/dev/null || true; "
    } else {
        ""
    };
    format!(
        "if command -v podman >/dev/null 2>&1; then RT=podman; \
         elif command -v docker >/dev/null 2>&1; then RT=docker; \
         else echo 'no container runtime (podman, docker), skipping' >&2; exit 1; fi; \
         RESULTS=$(mktemp) || exit 1; \
         for img in {images}; do \
           old=$($RT image inspect --format '{{{{.Id}}}}' \"$img\" 2>/dev/null || true); \
           if ! $RT pull \"$img\" 2>&1 | tail -3; then \
             printf 'FAIL\\t%s (pull failed)\\n' \"$img\" >>\"$RESULTS\"; continue; fi; \
           new=$($RT image inspect --format '{{{{.Id}}}}' \"$img\" 2>/dev/null || true); \
           if [ -z \"$new\" ]; then printf 'FAIL\\t%s (no digest after pull)\\n' \"$img\" >>\"$RESULTS\"; \
           elif [ -n \"$old\" ] && [ \"$old\" = \"$new\" ]; then \
             printf 'SAME\\t%s\\n' \"$img\" >>\"$RESULTS\"; \
           else printf 'MOVED\\t%s\\n' \"$img\" >>\"$RESULTS\"; fi; \
         done; \
         {prune}while IFS= read -r line || [ -n \"$line\" ]; do \
           [ -n \"$line\" ] || continue; \
           v=$(printf '%s' \"$line\" | cut -f1); n=$(printf '%s' \"$line\" | cut -f2); \
           printf '  %-5s %s\\n' \"$v\" \"$n\"; \
         done <\"$RESULTS\"; \
         if grep -q '^FAIL' \"$RESULTS\" 2>/dev/null; then rm -f \"$RESULTS\"; exit 1; fi; \
         rm -f \"$RESULTS\"",
        images = list.join(" "),
        prune = prune_step,
    )
}

#[cfg(test)]
mod tests {
    use super::image_command;

    #[test]
    fn image_pulls_and_compares_digests() {
        let cmd = image_command(&["searxng:latest".to_string()], false);
        assert!(cmd.contains("podman"), "{cmd}");
        assert!(cmd.contains("docker"), "{cmd}");
        assert!(cmd.contains("pull"), "{cmd}");
        assert!(cmd.contains("MOVED"), "{cmd}");
        assert!(cmd.contains("SAME"), "{cmd}");
        assert!(!cmd.contains("prune -f"), "{cmd}");
    }

    #[test]
    fn image_prunes_when_asked() {
        let cmd = image_command(&["a:1".to_string()], true);
        assert!(cmd.contains("prune -f"), "{cmd}");
    }

    #[test]
    fn image_fails_closed_on_pull_failure() {
        let cmd = image_command(&["a:1".to_string()], false);
        assert!(cmd.contains("pull failed"), "{cmd}");
        assert!(cmd.contains("exit 1"), "{cmd}");
    }

    #[test]
    fn image_names_are_quoted() {
        let cmd = image_command(&["a:1; evil".to_string()], false);
        assert!(cmd.contains("'a:1; evil'"), "{cmd}");
    }
}
