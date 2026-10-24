//! The `@build` step: build a pinned ref from source on the target.
//!
//! The native-build half of the binary catalog: check out the pinned ref,
//! build on the target (native glibc, no cross), probe the fresh binary,
//! back up the running one, install atomically, and restart the units that
//! were running. The manifest fields are data — the chain is owned by the
//! runner, so a new service adds one declarative block instead of a new
//! build script.

use super::host::quote;

/// The remote command for `@build`.
///
/// The script is pure shell (no helper verb). It never touches a unit that
/// was not running (restarting an inactive unit would start it), and a
/// fresh binary that fails its own probe aborts the run before anything
/// installed moves.
pub(super) fn build_command(build: &shellflow_core::BuildStep) -> String {
    let arts: Vec<String> = build.artifacts.iter().map(|a| quote(a)).collect();
    let dirs: Vec<String> = build.install_dirs.iter().map(|d| quote(d)).collect();
    let units_args: Vec<String> = build.units.iter().map(|u| quote(u)).collect();
    // An empty unit list must not render as `for u in ; do` (a syntax
    // error): with no units there is nothing to restart.
    let units_loop = if units_args.is_empty() {
        "echo 'no units to restart';".to_string()
    } else {
        format!(
            "for u in {} ; do \
             was=$(systemctl is-active \"$u\" 2>/dev/null || true); \
             if [ \"$was\" = active ]; then \
               if ! sudo systemctl restart \"$u\"; then \
                 echo \"restart $u failed\" >&2; sfw_rollback; exit 1; fi; \
               ok=0; i=0; \
               while [ \"$i\" -lt 30 ]; do \
                 if sudo systemctl is-active --quiet \"$u\" 2>/dev/null; then ok=1; break; fi; \
                 i=$((i + 1)); sleep 2; \
               done; \
               if [ \"$ok\" != 1 ]; then \
                 echo \"$u did not come back\" >&2; sfw_rollback; \
                 sudo systemctl restart \"$u\" >/dev/null 2>&1 || true; \
                 exit 1; fi; \
               echo \"$u restarted (active)\"; \
             else \
               echo \"$u was not running, left stopped\"; \
             fi; \
           done;",
            units_args.join(" ")
        )
    };
    format!(
        "SF_REPO={repo} SF_REF={git_ref} SF_BUILD={build} SF_PREP={prep} \
         SF_VFLAG={vflag} SF_MINGB={min_gb}; \
         sfw_probe() {{ b=\"$1\"; f=\"$2\"; \
           if [ -n \"$f\" ]; then out=$(\"$b\" \"$f\" 2>&1); verrc=$?; \
           else out=$(for sfw_f in --version -V -v -version version; do \
             if \"$b\" \"$sfw_f\" >/dev/null 2>&1; then \"$b\" \"$sfw_f\"; break; fi; done 2>&1); verrc=$?; fi; \
           if [ \"$verrc\" -ge 126 ]; then return 1; fi; \
           printf '%s' \"$out\" | head -1; }}; \
         WORK=${{SF_WORK:-$HOME/src/shellflow-builds}}; \
         NAME=$(basename \"$SF_REPO\" .git); \
         DEST=\"$WORK/$NAME\"; \
         sfw_fetch() {{ \
           n=0; \
           while [ \"$n\" -lt 3 ]; do \
             if git -C \"$DEST\" fetch origin --tags --force 2>/dev/null; then return 0; fi; \
             n=$((n + 1)); \
             echo \"fetch failed ($n/3), backing off\" >&2; \
             sleep $((n * 20)); \
           done; \
           return 1; \
         }}; \
         if [ -d \"$DEST/.git\" ]; then \
           if ! (cd \"$DEST\" && sfw_fetch 2>/dev/null \
             && (git checkout --detach --force \"origin/$SF_REF\" 2>/dev/null \
               || git checkout --detach --force \"$SF_REF\" 2>/dev/null)); then \
             echo \"fetch/checkout $SF_REF failed\" >&2; exit 1; fi; \
         else \
           mkdir -p \"$WORK\" || exit 1; \
           if ! git clone \"$SF_REPO\" \"$DEST\" 2>/dev/null; then echo 'clone failed' >&2; exit 1; fi; \
           if ! (cd \"$DEST\" && (git checkout --detach --force \"origin/$SF_REF\" 2>/dev/null \
             || git checkout --detach --force \"$SF_REF\" 2>/dev/null)); then \
             echo \"checkout $SF_REF failed\" >&2; exit 1; fi; \
         fi; \
         if [ -n \"$SF_PREP\" ]; then \
           echo 'running prep'; \
           if ! (cd \"$DEST\" && sh -c \"$SF_PREP\"); then echo 'prep failed' >&2; exit 1; fi; \
         fi; \
         TDIR=$(cd \"$DEST\" && cargo metadata --format-version 1 --no-deps 2>/dev/null \
           | tr ',' '\\n' | grep -m1 '\"target_directory\"' | cut -d'\"' -f4); \
         [ -n \"$TDIR\" ] || TDIR=\"$DEST/target\"; \
         AVAIL=$(df -Pk \"$TDIR\" 2>/dev/null | awk 'NR==2 {{print $4}}'); \
         case \"$AVAIL\" in ''|*[!0-9]*) AVAIL=0;; esac; \
         if [ \"$((AVAIL / 1024 / 1024))\" -lt \"$SF_MINGB\" ]; then \
           echo \"disk free below ${{SF_MINGB}}G, refusing to build\" >&2; exit 1; fi; \
         if ! (cd \"$DEST\" && CARGO_BUILD_JOBS=\"${{CARGO_BUILD_JOBS:-4}}\" \
           nice -n \"${{BUILD_NICE:-10}}\" sh -c \"$SF_BUILD\"); then \
           echo 'build failed' >&2; exit 1; fi; \
         for a in {artifacts}; do \
           case \"$a\" in *=*) src=\"${{a%%=*}}\"; nm=\"${{a#*=}}\";; *) src=\"$a\"; nm=$(basename \"$a\");; esac; \
           case \"$src\" in target/*) full=\"$TDIR/${{src#target/}}\";; *) full=\"$DEST/$src\";; esac; \
           [ -f \"$full\" ] || {{ echo \"artifact missing: $src\" >&2; exit 1; }}; \
           if ! sfw_probe \"$full\" \"$SF_VFLAG\" >/dev/null; then \
             echo \"preflight failed: $src runs nothing usable\" >&2; exit 1; fi; \
           echo \"preflight: $(sfw_probe \"$full\" \"$SF_VFLAG\")\"; \
         done; \
         SF_STAMP=$(date +%Y%m%d-%H%M%S); \
         for a in {artifacts}; do \
           case \"$a\" in *=*) src=\"${{a%%=*}}\"; nm=\"${{a#*=}}\";; *) src=\"$a\"; nm=$(basename \"$a\");; esac; \
           case \"$src\" in target/*) full=\"$TDIR/${{src#target/}}\";; *) full=\"$DEST/$src\";; esac; \
           for d in {dirs}; do \
             BK=\"/root/$nm-bin-backup-$SF_STAMP\"; \
             [ -f \"$d/$nm\" ] && {{ sudo install -d -m 0700 \"$BK\" 2>/dev/null || install -d -m 0700 \"$BK\"; \
               sudo cp -f \"$d/$nm\" \"$BK/$nm\" 2>/dev/null || cp -f \"$d/$nm\" \"$BK/$nm\" || exit 1; }}; \
             sudo cp -f \"$full\" \"$d/.$nm.new\" 2>/dev/null || cp -f \"$full\" \"$d/.$nm.new\" || exit 1; \
             sudo mv -f \"$d/.$nm.new\" \"$d/$nm\" 2>/dev/null || mv -f \"$d/.$nm.new\" \"$d/$nm\" || exit 1; \
             sudo chmod +x \"$d/$nm\" 2>/dev/null || chmod +x \"$d/$nm\" || exit 1; \
             echo \"installed $d/$nm\"; \
           done; \
         done; \
         sfw_rollback() {{ \
           echo 'rolling back'; \
           for a in {artifacts}; do \
             case \"$a\" in *=*) nm=\"${{a#*=}}\";; *) nm=$(basename \"$a\");; esac; \
             for d in {dirs}; do \
               BK=\"/root/$nm-bin-backup-$SF_STAMP\"; \
               if [ -f \"$BK/$nm\" ]; then \
                 sudo cp -f \"$BK/$nm\" \"$d/.$nm.rollback\" 2>/dev/null || cp -f \"$BK/$nm\" \"$d/.$nm.rollback\" || continue; \
                 sudo mv -f \"$d/.$nm.rollback\" \"$d/$nm\" 2>/dev/null || mv -f \"$d/.$nm.rollback\" \"$d/$nm\" || continue; \
                 echo \"restored $d/$nm\"; \
               fi; \
             done; \
           done; }}; \
         {units_loop} \
         echo 'build step complete'",
        repo = quote(&build.repo),
        git_ref = quote(&build.git_ref),
        build = quote(&build.build_cmd),
        prep = quote(build.prep_cmd.as_deref().unwrap_or("")),
        artifacts = arts.join(" "),
        dirs = dirs.join(" "),
        units_loop = units_loop,
        vflag = quote(&build.version_flag),
        min_gb = build.min_free_gb,
    )
}

#[cfg(test)]
mod tests {
    use super::build_command;

    fn sample() -> String {
        build_command(&shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("api"),
            repo: "https://github.com/x/y.git".to_string(),
            git_ref: "abc123".to_string(),
            build_cmd: "cargo build --release -p app".to_string(),
            prep_cmd: None,
            artifacts: vec!["target/release/app".to_string()],
            install_dirs: vec!["/opt/app/bin".to_string()],
            units: vec!["app.service".to_string()],
            version_flag: "--version".to_string(),
            min_free_gb: 8,
            timeout: None,
        })
    }

    #[test]
    fn build_checks_out_builds_probes_and_installs() {
        let cmd = sample();
        assert!(cmd.contains("sfw_fetch"), "{cmd}");
        assert!(cmd.contains("fetch origin --tags"), "{cmd}");
        assert!(cmd.contains("checkout --detach"), "{cmd}");
        // Branch REFs resolve via the freshly fetched origin/* first: a
        // detached checkout of the local branch name alone could sit on a
        // stale tip while origin moved on.
        assert!(cmd.contains("origin/$SF_REF"), "{cmd}");
        assert!(cmd.contains("cargo build --release"), "{cmd}");
        assert!(cmd.contains("disk free below"), "{cmd}");
        assert!(cmd.contains("preflight"), "{cmd}");
        assert!(cmd.contains("mv -f"), "{cmd}");
    }

    #[test]
    fn build_never_starts_a_stopped_unit() {
        let cmd = sample();
        assert!(cmd.contains("was not running, left stopped"), "{cmd}");
    }

    #[test]
    fn build_probes_with_declared_flag_first() {
        let cmd = sample();
        assert!(cmd.contains("--version"), "{cmd}");
        // …and falls back to the flag chain when no flag is declared.
        let noflag = build_command(&shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("api"),
            repo: "https://github.com/x/y.git".to_string(),
            git_ref: "r".to_string(),
            build_cmd: "make".to_string(),
            prep_cmd: None,
            artifacts: vec!["app".to_string()],
            install_dirs: vec!["/opt/a".to_string()],
            units: vec![],
            version_flag: String::new(),
            min_free_gb: 8,
            timeout: None,
        });
        assert!(noflag.contains("--version -V -v -version version"), "{noflag}");
    }

    #[test]
    fn build_values_are_quoted() {
        let cmd = build_command(&shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("api"),
            repo: "https://github.com/x/y.git".to_string(),
            git_ref: "r; evil".to_string(),
            build_cmd: "make".to_string(),
            prep_cmd: None,
            artifacts: vec!["a".to_string()],
            install_dirs: vec!["/opt/a".to_string()],
            units: vec![],
            version_flag: String::new(),
            min_free_gb: 8,
            timeout: None,
        });
        assert!(cmd.contains("'r; evil'"), "{cmd}");
    }

    #[test]
    fn build_supports_renamed_artifacts() {
        let cmd = sample();
        assert!(cmd.contains("%%=*"), "{cmd}");
    }

    #[test]
    fn build_installs_renamed_artifacts_under_the_new_name() {
        let mut step = shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("ai"),
            repo: "https://github.com/bnb-chain/reth.git".to_string(),
            git_ref: "5710c1f".to_string(),
            build_cmd: "cargo build --release -p reth".to_string(),
            prep_cmd: None,
            artifacts: vec!["target/release/reth=reth-bsc".to_string()],
            install_dirs: vec!["/usr/local/bin".to_string()],
            units: vec!["bsc-reth-testnet.service".to_string()],
            version_flag: "--version".to_string(),
            min_free_gb: 20,
            timeout: None,
        };
        let cmd = build_command(&step);
        // The installed file and its backup carry the *new* name; the
        // built file keeps the workspace name.
        assert!(cmd.contains("$d/.$nm.new"), "{cmd}");
        assert!(cmd.contains("/root/$nm-bin-backup-$SF_STAMP"), "{cmd}");
        step.artifacts = vec!["target/release/reth".to_string()];
        let plain = build_command(&step);
        assert!(plain.contains("nm=$(basename \"$a\")"), "{plain}");
    }

    #[test]
    fn build_retries_fetch_with_backoff() {
        let cmd = sample();
        assert!(cmd.contains("backing off"), "{cmd}");
        assert!(cmd.contains("sleep $((n * 20))"), "{cmd}");
    }

    #[test]
    fn build_runs_quietly_beside_online_services() {
        // Production builds must not starve online services: the build runs
        // nicened with capped cargo parallelism (both overridable from the
        // environment, matching the old playbook's BUILD_NICE/BUILD_JOBS).
        let cmd = sample();
        assert!(cmd.contains("nice -n"), "{cmd}");
        assert!(cmd.contains("CARGO_BUILD_JOBS"), "{cmd}");
    }

    #[test]
    fn every_for_loop_opens_with_do() {
        // The generated script is one long `;`-separated line: a `for`
        // without a following `do` is a zsh parse error (`for u in X do`).
        // Split on `;` and require every `for` segment's successor to open
        // the loop body.
        let cmd = sample();
        let segs: Vec<&str> = cmd.split(';').collect();
        let mut fors = 0;
        for (i, seg) in segs.iter().enumerate() {
            if seg.trim_start().starts_with("for ") {
                fors += 1;
                let next = segs.get(i + 1).map(|s| s.trim_start()).unwrap_or("");
                assert!(
                    next.starts_with("do ") || next.starts_with("do\t") || next == "do",
                    "for without do: {seg} || {next}"
                );
            }
        }
        assert!(fors >= 3, "expected several for loops, got {fors}");
    }

    #[test]
    fn build_without_units_emits_no_loop() {
        let mut step = shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("api"),
            repo: "https://github.com/x/y.git".to_string(),
            git_ref: "r".to_string(),
            build_cmd: "make".to_string(),
            prep_cmd: None,
            artifacts: vec!["a".to_string()],
            install_dirs: vec!["/opt/a".to_string()],
            units: vec![],
            version_flag: String::new(),
            min_free_gb: 8,
            timeout: None,
        };
        let cmd = build_command(&step);
        assert!(cmd.contains("no units to restart"), "{cmd}");
        assert!(!cmd.contains("for u in"), "{cmd}");
        step.units = vec!["a.service".to_string()];
        let with_units = build_command(&step);
        assert!(with_units.contains("for u in 'a.service'"), "{with_units}");
    }

    #[test]
    fn build_lists_are_literal_words_safe_under_zsh() {
        // `for x in $VAR` does not word-split under zsh, so the artifact,
        // directory, and unit lists are baked in as literal words. A runtime
        // variable expansion here would run the whole loop once at best.
        let cmd = sample();
        assert!(cmd.contains("for a in 'target/release/app'"), "{cmd}");
        assert!(cmd.contains("for d in '/opt/app/bin'"), "{cmd}");
        assert!(cmd.contains("for u in 'app.service' ; do"), "{cmd}");
        assert!(!cmd.contains("for u in ; do"), "{cmd}");
        assert!(!cmd.contains("for a in $"), "{cmd}");
        assert!(!cmd.contains("for d in $"), "{cmd}");
        assert!(!cmd.contains("for u in $"), "{cmd}");
    }

    #[test]
    fn build_rolls_back_and_restarts_on_failure() {
        let cmd = sample();
        assert!(cmd.contains("sfw_rollback"), "{cmd}");
        assert!(cmd.contains("restored $d/$nm"), "{cmd}");
        // A unit that does not come back gets its old binary restored and
        // one more start attempt before the step fails. Slow starters get a
        // bounded poll, not a single shot.
        assert!(cmd.contains("did not come back"), "{cmd}");
        assert!(cmd.contains("while [ \"$i\" -lt 30 ]"), "{cmd}");
    }

    #[test]
    fn build_runs_prep_between_checkout_and_build() {
        let mut step = shellflow_core::BuildStep {
            name: None,
            target: shellflow_core::Target::new("api"),
            repo: "https://github.com/x/y.git".to_string(),
            git_ref: "r".to_string(),
            build_cmd: "make".to_string(),
            prep_cmd: Some("git submodule update --init --recursive".to_string()),
            artifacts: vec!["a".to_string()],
            install_dirs: vec!["/opt/a".to_string()],
            units: vec![],
            version_flag: String::new(),
            min_free_gb: 8,
            timeout: None,
        };
        let cmd = build_command(&step);
        assert!(cmd.contains("submodule update --init --recursive"), "{cmd}");
        assert!(cmd.contains("running prep"), "{cmd}");
        step.prep_cmd = None;
        let skipped = build_command(&step);
        assert!(skipped.contains("if [ -n \"$SF_PREP\" ]"), "{skipped}");
    }
}
