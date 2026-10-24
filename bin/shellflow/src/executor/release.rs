//! The `@release` step: track a GitHub release and install on drift.
//!
//! Replaces the hand-written version-compare blocks (`--version` output vs
//! the `releases/latest` redirect) that every binary-from-release service
//! repeats: the runner resolves the newest tag, compares it against the
//! installed binary, and downloads the matching asset only when they differ.
//! No download means nothing downstream needs a restart.

use super::host::quote;

/// The remote command for `@release`.
///
/// The script is pure shell (no helper verb): it resolves, compares,
/// downloads, extracts, and atomically installs. The asset pattern supports
/// `{tag}` (the `v`-prefixed tag) and `{version}` (the tag without `v`).
/// `--installed-cmd` is either a bare binary path (the runner tries the
/// version-flag chain `--version -V -v -version version`, so a service
/// without `--version` still gets a probe) or a full command, run as-is.
/// `base_url` overrides the download host for vendor CDNs.
pub(super) fn release_command(
    repo: &str,
    installed_cmd: &str,
    asset: &str,
    to_dir: &str,
    base_url: Option<&str>,
) -> String {
    let default_base = format!("https://github.com/{repo}/releases/download");
    let base = base_url.unwrap_or(&default_base);
    format!(
        "SF_REPO={repo} SF_CMD={cmd} SF_ASSET={asset} SF_DIR={dir} SF_BASE={base}; \
         sfw_latest_tag() {{ \
           loc=$(curl -fsSI --connect-timeout 10 --max-time 30 \
             \"https://github.com/$SF_REPO/releases/latest\" 2>/dev/null \
             | tr -d '\\r' | grep -i '^location:' | tail -1); \
           tag=$(printf '%s' \"$loc\" | sed -n 's#.*/tag/\\(v[0-9][0-9.]*\\)$#\\1#p'); \
           [ -n \"$tag\" ] && {{ printf '%s' \"$tag\"; return 0; }}; \
           curl -fsSL --connect-timeout 10 --max-time 30 \
             \"https://api.github.com/repos/$SF_REPO/releases/latest\" 2>/dev/null \
             | sed -n 's/.*\"tag_name\"[[:space:]]*:[[:space:]]*\"\\(v[0-9][0-9.]*\\)\".*/\\1/p' \
             | head -1; \
         }}; \
         sfw_probe() {{ \
           case \"$SF_CMD\" in \
           *\\ *) out=$(sh -c \"$SF_CMD\" 2>&1); verrc=$?;; \
           *) out=$(for sfw_f in --version -V -v -version version; do \
                  if \"$SF_CMD\" \"$sfw_f\" >/dev/null 2>&1; then \"$SF_CMD\" \"$sfw_f\"; break; fi; \
                done 2>&1); verrc=$?;; \
           esac; \
           if [ \"$verrc\" -ge 126 ]; then return 1; fi; \
           printf '%s' \"$out\" | grep -oE 'v?[0-9]+\\.[0-9]+\\.[0-9]+' | head -1; \
         }}; \
         INSTALLED=$(sfw_probe || true); \
         LATEST=$(sfw_latest_tag || true); \
         echo \"installed=${{INSTALLED:-unknown}} latest=${{LATEST:-unknown}}\"; \
         if [ -z \"$LATEST\" ]; then echo 'could not resolve the latest release; skipping'; exit 0; fi; \
         IV=$(printf '%s' \"$INSTALLED\" | sed 's/^v//'); \
         LV=$(printf '%s' \"$LATEST\" | sed 's/^v//'); \
         if [ -n \"$INSTALLED\" ] && [ \"$IV\" = \"$LV\" ]; then \
           echo 'already up to date'; exit 0; \
         fi; \
         TAG=\"$LATEST\"; VER=$(printf '%s' \"$LATEST\" | sed 's/^v//'); \
         FILE=$(printf '%s' \"$SF_ASSET\" | sed \"s/{{tag}}/$TAG/g; s/{{version}}/$VER/g\"); \
         echo \"updating to $TAG ($FILE)\"; \
         TMP=$(mktemp -d) || exit 1; \
         if ! curl -fsSL --connect-timeout 10 --max-time 120 \
           \"$SF_BASE/$TAG/$FILE\" -o \"$TMP/pkg\"; then \
           echo \"download failed\" >&2; rm -rf \"$TMP\"; exit 1; \
         fi; \
         (cd \"$TMP\" && (tar -xzf pkg 2>/dev/null || unzip -o -q pkg 2>/dev/null)) \
           || {{ echo 'extraction failed' >&2; rm -rf \"$TMP\"; exit 1; }}; \
         n=0; \
         for f in \"$TMP\"/*; do \
           [ -f \"$f\" ] && [ -x \"$f\" ] || continue; \
           b=$(basename \"$f\"); \
           sudo cp -f \"$f\" \"$SF_DIR/.$b.new\" && sudo mv -f \"$SF_DIR/.$b.new\" \"$SF_DIR/$b\" \
             && sudo chmod +x \"$SF_DIR/$b\" && n=$((n + 1)) && echo \"installed $b\"; \
         done; \
         rm -rf \"$TMP\"; \
         if [ \"$n\" = 0 ]; then echo 'no executable found in the asset' >&2; exit 1; fi",
        repo = quote(repo),
        cmd = quote(installed_cmd),
        asset = quote(asset),
        dir = quote(to_dir),
        base = quote(base),
    )
}

#[cfg(test)]
mod tests {
    use super::release_command;

    #[test]
    fn release_resolves_compares_and_installs_atomically() {
        let cmd = release_command(
            "sigoden/dufs",
            "/opt/dufs/bin/dufs --version",
            "dufs-{tag}-x86_64-unknown-linux-musl.tar.gz",
            "/opt/dufs/bin",
            None,
        );
        assert!(cmd.contains("releases/latest"), "{cmd}");
        assert!(cmd.contains("already up to date"), "{cmd}");
        assert!(cmd.contains("{tag}"), "{cmd}");
        // Atomic install: write beside the destination, then rename.
        assert!(cmd.contains(".new"), "{cmd}");
        assert!(cmd.contains("mv -f"), "{cmd}");
        // A missing release resolution skips rather than failing the run.
        assert!(cmd.contains("skipping"), "{cmd}");
        // The default download host is the repo's GitHub releases.
        assert!(cmd.contains("github.com/sigoden/dufs/releases/download"), "{cmd}");
    }

    #[test]
    fn release_supports_a_vendor_download_host() {
        let cmd = release_command(
            "openobserve/openobserve",
            "/opt/openobserve/bin/openobserve --version",
            "openobserve-{tag}-linux-amd64.tar.gz",
            "/opt/openobserve/bin",
            Some("https://downloads.openobserve.ai/releases/openobserve"),
        );
        assert!(cmd.contains("downloads.openobserve.ai/releases/openobserve"), "{cmd}");
        assert!(!cmd.contains("github.com/openobserve/openobserve/releases/download"), "{cmd}");
    }

    #[test]
    fn release_compares_versions_without_the_v_prefix() {
        // `dufs --version` prints `0.47.0` while the tag is `v0.47.0`: the
        // comparison strips the prefix on both sides, or every run would
        // re-download the installed version.
        let cmd = release_command("o/r", "x", "a-{tag}.tar.gz", "/tmp", None);
        assert!(cmd.contains("sed 's/^v//'"), "{cmd}");
        assert!(cmd.contains("[ \"$IV\" = \"$LV\" ]"), "{cmd}");
    }

    #[test]
    fn release_installs_through_the_staging_dir_variable() {
        // The install loop must use `$SF_DIR`, not the quoted literal: a
        // literal `'...'` in the path makes every copy fail.
        let cmd = release_command("o/r", "x", "a-{tag}.tar.gz", "/opt/x/bin", None);
        assert!(cmd.contains("$SF_DIR/.$b.new"), "{cmd}");
        assert!(!cmd.contains("'/opt/x/bin'/."), "{cmd}");
    }

    #[test]
    fn release_probes_version_flags_in_order() {
        let cmd = release_command("o/r", "x", "a-{tag}.tar.gz", "/tmp", None);
        assert!(cmd.contains("--version -V -v -version version"), "{cmd}");
        assert!(cmd.contains("126"), "{cmd}");
    }

    #[test]
    fn release_runs_a_full_command_as_is() {
        let cmd = release_command("o/r", "x --version", "a-{tag}.tar.gz", "/tmp", None);
        assert!(cmd.contains("sh -c"), "{cmd}");
    }

    #[test]
    fn release_values_are_quoted() {
        let cmd = release_command("o/r", "x; evil", "a.tar.gz", "/tmp", None);
        assert!(cmd.contains("'x; evil'"), "{cmd}");
    }
}
