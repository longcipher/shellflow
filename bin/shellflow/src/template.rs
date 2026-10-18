//! `shellflow template` — cross-check `${KEY}` templates against encrypted
//! env files.
//!
//! A template rendered by the `cred-env` helper on the target must reference
//! exactly the credentials the unit imports. `template check` validates that
//! on the controller, before a deploy, so a typo fails at authoring time
//! instead of at unit start.

use std::fs;

use eyre::{Result, WrapErr, eyre};
use shellflow_core::template_keys;
use shellflow_secrets::{
    crypto::decrypt_bytes,
    env::parse_env_file,
    identity::{effective_identity_path, load_x25519_identity},
};

use crate::cli::{TemplateCheckArgs, TemplateCmd};

/// Run a `template` subcommand.
///
/// # Errors
///
/// Propagates I/O, identity, and decryption errors; `check` fails when the
/// template references a key that the env file does not provide.
pub(crate) fn run(cmd: &TemplateCmd) -> Result<()> {
    match cmd {
        TemplateCmd::Check(args) => check(args),
    }
}

fn check(args: &TemplateCheckArgs) -> Result<()> {
    let content = fs::read_to_string(&args.template)
        .wrap_err_with(|| format!("failed to read template `{}`", args.template.display()))?;
    let used = template_keys(&content);

    let cipher = fs::read(&args.file)
        .wrap_err_with(|| format!("failed to read secrets file `{}`", args.file.display()))?;
    let id_path = effective_identity_path(args.identity.as_deref());
    let identity = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
    let plain = decrypt_bytes(&cipher, &identity)
        .wrap_err_with(|| format!("failed to decrypt `{}`", args.file.display()))?;
    let plain = String::from_utf8(plain).wrap_err("decrypted file is not valid UTF-8")?;
    let env_keys: Vec<String> = parse_env_file(&plain)
        .wrap_err("malformed env file")?
        .into_iter()
        .map(|(k, _)| k)
        .collect();

    // Missing keys are fatal: `cred-env render` would fail the unit at start.
    let missing: Vec<&String> = used.iter().filter(|k| !env_keys.contains(k)).collect();
    if !missing.is_empty() {
        return Err(eyre!(
            "template `{}` references keys missing from `{}`: {}",
            args.template.display(),
            args.file.display(),
            missing.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", "),
        ));
    }

    // Unused keys are a warning: the credential is imported but never
    // substituted, which usually means a stale key or a stale template.
    for key in env_keys.iter().filter(|k| !used.contains(k)) {
        println!("note: {key} is in the env file but not referenced by the template");
    }
    println!(
        "OK: {} key(s) referenced by the template, all present in {}",
        used.len(),
        args.file.display()
    );
    Ok(())
}
