//! The credential store: its layout, its keys, and the value-based leak check.
//!
//! A plaintext credential never reaches a command line, the journal, or the
//! operator's log: the comparison happens in this process.

use super::{
    BTreeSet, CREDSTORE_ROOT, Command, HostAssertCredstoreArgs, HostAssertNoLeakArgs,
    HostCredstoreArgs, HostError, Path, Stdio, fs,
    privileged::{dir_exists_elevated, list_dir_elevated, systemctl_output},
    probe::{all_unit_files, main_pid},
    strip_directive, validate_unit,
};

/// Seal the service's credential store and check it against the unit.
pub(super) fn credstore(args: &HostCredstoreArgs) -> Result<(), HostError> {
    validate_unit(&args.service)?;
    // The credential values travel in the environment of this process (the
    // controller injects them from `@secrets`); the helper re-executes itself
    // under `sudo --preserve-env=<exact key list>` to seal them.
    crate::cred_env::credstore_install(&args.service, None)
        .map_err(|err| HostError::internal(format!("cannot seal the credential store: {err}")))?;
    verify_credstore(&args.service, &args.require)?;
    Ok(())
}

/// Check that the credential store agrees with the unit's declaration.
///
/// The unit names the credential keys it wants; the store holds the values.
/// A key in one and not the other is a unit that fails to start with a
/// cryptic systemd error — this turns it into a readable failure.
pub(super) fn verify_credstore(service: &str, require: &[String]) -> Result<(), HostError> {
    let store = Path::new(CREDSTORE_ROOT).join(service);
    if !dir_exists_elevated(&store) {
        return Err(HostError::failed(format!(
            "the credential store {} does not exist",
            store.display()
        )));
    }
    let held = store_keys(&store)?;
    let declared = declared_credential_keys(service);
    let Some(disagreement) = store_disagreement(require, &declared, &held) else {
        crate::ui::report!(
            "==> credential store {service} agrees with the unit ({} keys)",
            held.len()
        );
        return Ok(());
    };
    Err(HostError::failed(format!(
        "the credential store {}: {}",
        store.display(),
        match &disagreement {
            Disagreement::MissingFromStore(keys) => format!("does not hold: {}", keys.join(", ")),
            Disagreement::DeclaredButAbsent(keys) => format!(
                "the unit declares credential keys the store does not hold: {}",
                keys.join(", ")
            ),
            Disagreement::HeldButUnimported(keys) => {
                format!("holds keys no unit imports: {}", keys.join(", "))
            }
        }
    )))
}

/// One way a credential store and the unit that reads it can disagree.
///
/// The three cases are reported separately because the fix differs: a key the
/// deploy promised and the store lacks is a failed deploy, a key the unit
/// declares and the store lacks is a unit that will not start, and a key
/// nobody imports is a rotation nobody picked up.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Disagreement {
    /// `--require` named a key the store does not hold.
    MissingFromStore(Vec<String>),
    /// The unit declares a key the store does not hold.
    DeclaredButAbsent(Vec<String>),
    /// The store holds a key no unit imports.
    HeldButUnimported(Vec<String>),
}

/// Whether the store and the unit agree, checked in that order.
///
/// The order matters: "the deploy did not deliver" is the diagnosis an
/// operator can act on, so it wins over "the unit asks for too much".
fn store_disagreement(
    required: &[String],
    declared: &BTreeSet<String>,
    held: &BTreeSet<String>,
) -> Option<Disagreement> {
    let absent = |keys: &BTreeSet<String>| -> Vec<String> {
        keys.iter().filter(|key| !held.contains(*key)).cloned().collect()
    };
    let required: BTreeSet<String> = required.iter().cloned().collect();
    let missing = absent(&required);
    if !missing.is_empty() {
        return Some(Disagreement::MissingFromStore(missing));
    }
    let undeclared = absent(declared);
    if !undeclared.is_empty() {
        return Some(Disagreement::DeclaredButAbsent(undeclared));
    }
    let unused: Vec<String> = held.iter().filter(|key| !declared.contains(*key)).cloned().collect();
    if !unused.is_empty() {
        return Some(Disagreement::HeldButUnimported(unused));
    }
    None
}

/// Assert that the credential store exists and is well formed.
pub(super) fn assert_credstore(args: &HostAssertCredstoreArgs) -> Result<(), HostError> {
    validate_unit(&args.service)?;
    verify_credstore(&args.service, &[])?;
    Ok(())
}

/// The credential keys the unit declares.
pub(super) fn declared_credential_keys(service: &str) -> BTreeSet<String> {
    // The store names the place the keys live, and every unit that imports
    // from it says so in its own path. The units are found by that path,
    // not by name: the wiring lives in a drop-in, a service may own several
    // units, and two services may share one store.
    let store = format!("{CREDSTORE_ROOT}/{service}/");
    let mut keys = BTreeSet::new();
    for file in all_unit_files() {
        let Ok(text) = fs::read_to_string(&file) else {
            continue;
        };
        for line in text.lines() {
            let Some(rest) = strip_directive(line, "LoadCredentialEncrypted=") else {
                continue;
            };
            let Some((key, path)) = rest.split_once(':') else {
                continue;
            };
            if path.trim().starts_with(&store) {
                keys.insert(key.trim().to_string());
            }
        }
    }
    keys
}

/// The credential keys the store holds.
pub(super) fn store_keys(store: &Path) -> Result<BTreeSet<String>, HostError> {
    let mut keys = BTreeSet::new();
    for entry in list_dir_elevated(store)? {
        let Some(name) = entry.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        keys.insert(name.to_string());
    }
    Ok(keys)
}

/// Decrypt one credential from the store.
///
/// The plaintext is held in memory only, and it is never printed.
pub(super) fn decrypt_credential(path: &Path) -> Result<String, HostError> {
    let path_text = path.to_string_lossy().into_owned();
    let out = super::privileged::sudo_output(&["systemd-creds", "decrypt", &path_text])
        .map_err(|err| HostError::internal(format!("cannot run `systemd-creds`: {err}")))?;
    if !out.status.success() {
        return Err(HostError::internal("`systemd-creds decrypt` failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Assert that no credential value appears in the unit's journal or argv.
///
/// The check is **value based**: the helper decrypts the service's own
/// credential store and looks for the real values. A playbook therefore
/// needs no per-service regular expression, and the plaintext never reaches
/// the script, the command line, or the operator's log.
pub(super) fn assert_no_leak(args: &HostAssertNoLeakArgs) -> Result<(), HostError> {
    let unit = shellflow_text::normalize_unit(&args.unit);
    validate_unit(&unit)?;
    let service = unit.trim_end_matches(".service");
    let store = Path::new(CREDSTORE_ROOT).join(service);
    if !dir_exists_elevated(&store) {
        crate::ui::report!("==> {service} has no credential store: nothing to leak");
        return Ok(());
    }

    let mut values: Vec<String> = Vec::new();
    for key in store_keys(&store)? {
        let Ok(value) = decrypt_credential(&store.join(&key)) else {
            continue;
        };
        if is_leakable(&value) {
            values.push(value);
        }
    }
    if values.is_empty() {
        crate::ui::report!("==> {service} has no decryptable credential: nothing to leak");
        return Ok(());
    }

    let haystacks = collect_leak_sources(&unit, args.lines);
    let leaks = leaked_sources(&values, &haystacks);
    if leaks.is_empty() {
        crate::ui::report!("==> no credential value of {service} appears in the journal or argv");
        return Ok(());
    }
    Err(HostError::failed(format!(
        "a credential value of {service} appears in: {}",
        leaks.join(", ")
    )))
}

/// Whether a value is long enough to be worth looking for.
///
/// A three-character secret matches half of the journal by accident; reporting
/// those would make the assertion unusable, so short values are skipped rather
/// than matched.
const fn is_leakable(value: &str) -> bool {
    value.len() >= 4
}

/// The sources a value leaked into: sorted, deduplicated, and named.
///
/// Named rather than counted: "the environment of app.service" is actionable,
/// "2 leaks" is not.
fn leaked_sources(values: &[String], haystacks: &[(String, String)]) -> Vec<String> {
    let mut leaks: Vec<String> = Vec::new();
    for value in values {
        for (source, text) in haystacks {
            if text.contains(value.as_str()) {
                leaks.push(source.clone());
            }
        }
    }
    leaks.sort();
    leaks.dedup();
    leaks
}

/// The texts a credential value could leak into.
pub(super) fn collect_leak_sources(unit: &str, lines: u64) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();

    let journal = Command::new("journalctl")
        .arg(format!("-u{unit}"))
        .arg("--no-pager")
        .arg(format!("-n{lines}"))
        .stdin(Stdio::null())
        .output();
    if let Ok(out_journal) = journal {
        out.push((
            format!("the journal of {unit}"),
            String::from_utf8_lossy(&out_journal.stdout).into_owned(),
        ));
    }

    // The command line: `systemctl show` reports the *effective* ExecStart,
    // which is where a secret passed as an argument would show up.
    if let Ok(out_show) = systemctl_output(&["show", unit, "-p", "ExecStart", "-p", "Environment"])
    {
        out.push((
            format!("the command line of {unit}"),
            String::from_utf8_lossy(&out_show.stdout).into_owned(),
        ));
    }

    // The process environment: `/proc/<pid>/environ` is readable by the same
    // uid, so a secret in `Environment=` is visible there too.
    if let Ok(pid) = main_pid(unit) &&
        let Ok(text) = fs::read_to_string(format!("/proc/{pid}/environ"))
    {
        out.push((format!("the environment of {unit}"), text));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs};

    use super::{
        Disagreement, declared_credential_keys, is_leakable, leaked_sources, store_disagreement,
        store_keys,
    };

    fn set(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|k| (*k).to_string()).collect()
    }

    fn keys(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|k| (*k).to_string()).collect()
    }

    #[test]
    fn a_store_that_matches_the_unit_agrees() {
        assert_eq!(store_disagreement(&keys(&["TOKEN"]), &set(&["TOKEN"]), &set(&["TOKEN"])), None);
    }

    #[test]
    fn a_promised_key_the_store_lacks_is_the_first_diagnosis() {
        // A deploy that did not deliver is the actionable one, so it is
        // reported before "the unit asks for too much".
        assert_eq!(
            store_disagreement(&keys(&["TOKEN"]), &set(&["TOKEN"]), &set(&[])),
            Some(Disagreement::MissingFromStore(keys(&["TOKEN"])))
        );
    }

    #[test]
    fn a_key_the_unit_declares_and_the_store_lacks_is_next() {
        assert_eq!(
            store_disagreement(&[], &set(&["TOKEN", "API_KEY"]), &set(&["TOKEN"])),
            Some(Disagreement::DeclaredButAbsent(keys(&["API_KEY"])))
        );
    }

    #[test]
    fn a_key_nobody_imports_is_a_rotation_nobody_picked_up() {
        assert_eq!(
            store_disagreement(&[], &set(&["TOKEN"]), &set(&["TOKEN", "OLD"])),
            Some(Disagreement::HeldButUnimported(keys(&["OLD"])))
        );
    }
    #[test]
    fn a_handful_of_characters_is_not_a_secret_worth_hunting() {
        assert!(!is_leakable(""), "an empty value");
        assert!(!is_leakable("abc"), "shorter than four");
        assert!(is_leakable("abcd"));
    }

    #[test]
    fn a_leak_is_reported_as_the_source_that_holds_it() {
        let haystacks = vec![
            ("the journal of app.service".to_string(), "starting up".to_string()),
            ("the environment of app.service".to_string(), "TOKEN=s3cr3t-value".to_string()),
        ];
        // No value, no leak — even with sources to search.
        assert!(leaked_sources(&[], &haystacks).is_empty());
        assert!(leaked_sources(&["not-there".to_string()], &haystacks).is_empty());
        // One value in one source, reported once, by name.
        assert_eq!(
            leaked_sources(&["s3cr3t-value".to_string()], &haystacks),
            vec!["the environment of app.service".to_string()]
        );
        // Two values in the same source: one finding, not two.
        assert_eq!(
            leaked_sources(&["starting".to_string(), "up".to_string()], &haystacks),
            vec!["the journal of app.service".to_string()]
        );
        // Both sources, sorted.
        assert_eq!(
            leaked_sources(&["up".to_string(), "s3cr3t-value".to_string()], &haystacks),
            vec![
                "the environment of app.service".to_string(),
                "the journal of app.service".to_string()
            ]
        );
    }

    #[test]
    fn a_store_holds_its_keys() {
        // The `.seal-fingerprint` marker is bookkeeping, not a credential: a
        // store that counted it would report one phantom key per service.
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("TOKEN"), b"x").expect("write");
        fs::write(dir.path().join("API_KEY"), b"x").expect("write");
        fs::write(dir.path().join(".seal-fingerprint"), b"x").expect("write");
        let keys = store_keys(dir.path()).expect("keys");
        assert_eq!(keys.len(), 2);
        assert!(keys.contains("TOKEN"));
        assert!(keys.contains("API_KEY"));
    }

    #[test]
    fn a_unit_without_credentials_declares_nothing() {
        assert!(declared_credential_keys("definitely-not-a-unit.service").is_empty());
    }
}
