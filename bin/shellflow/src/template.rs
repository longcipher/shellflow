//! `shellflow template` — cross-check `${KEY}` templates against encrypted
//! env files.
//!
//! A template rendered by the `cred-env` helper on the target must reference
//! exactly the credentials the unit imports. `template check` validates that
//! on the controller, before a deploy, so a typo fails at authoring time
//! instead of at unit start.

use std::{collections::HashMap, fs};

use eyre::{Result, WrapErr, eyre};
use shellflow_core::{render_template, template_keys};
use shellflow_secrets::{
    crypto::decrypt_string,
    env::parse_env_file,
    identity::{effective_identity_path, load_x25519_identity},
};

use crate::{
    cli::{RenderFormat, TemplateCheckArgs, TemplateCmd, TemplateRenderArgs},
    ui::Ui,
};

/// Run a `template` subcommand.
///
/// # Errors
///
/// Propagates I/O, identity, and decryption errors; `check` fails when the
/// template references a key that the env file does not provide.
pub(crate) fn run(cmd: &TemplateCmd, ui: &Ui) -> Result<()> {
    match cmd {
        TemplateCmd::Check(args) => check(args, ui),
        TemplateCmd::Render(args) => render(args, ui),
    }
}

/// Decrypt an env file into an ordered key/value map.
fn decrypt_env(
    file: &std::path::Path,
    identity: Option<&std::path::Path>,
) -> Result<Vec<(String, String)>> {
    let cipher = fs::read(file)
        .wrap_err_with(|| format!("failed to read secrets file `{}`", file.display()))?;
    let id_path = effective_identity_path(identity).map_err(|err| eyre!("{err}"))?;
    let id = load_x25519_identity(&id_path)
        .map_err(|err| eyre!("{err} (identity: {})", id_path.display()))?;
    let plain = decrypt_string(&cipher, &id)
        .wrap_err_with(|| format!("failed to decrypt `{}`", file.display()))?;
    parse_env_file(&plain).wrap_err("malformed env file")
}

fn check(args: &TemplateCheckArgs, ui: &Ui) -> Result<()> {
    let content = fs::read_to_string(&args.template)
        .wrap_err_with(|| format!("failed to read template `{}`", args.template.display()))?;
    let used = template_keys(&content);

    let pairs = decrypt_env(&args.file, args.identity.as_deref())?;
    let env_keys: Vec<String> = pairs.into_iter().map(|(k, _)| k).collect();

    // Missing keys are fatal: `cred-env render` would fail the unit at start.
    let missing: Vec<&String> = used.iter().filter(|k| !env_keys.contains(k)).collect();
    if !missing.is_empty() {
        return Err(eyre!(
            "template `{}` references keys missing from `{}`: {}",
            args.template.display(),
            args.file.display(),
            missing.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }

    // Unused keys are a warning: the credential is imported but never
    // substituted, which usually means a stale key or a stale template.
    for key in env_keys.iter().filter(|k| !used.contains(k)) {
        ui.note(&format!("note: {key} is in the env file but not referenced by the template"));
    }
    ui.note(&format!(
        "OK: {} key(s) referenced by the template, all present in {}",
        used.len(),
        args.file.display()
    ));
    Ok(())
}

/// Render a template against an encrypted env file entirely in memory.
///
/// Nothing is written and no value is ever printed: the summary reports key
/// names, byte counts, and (with `--format`) structural validity only.
/// Missing keys fail exactly like `cred-env render` would on the target, and
/// `--format toml|json` additionally parses the substituted output, catching
/// structural accidents (a dropped newline joining two lines, an unclosed
/// quote) that key-set comparison cannot see.
fn render(args: &TemplateRenderArgs, ui: &Ui) -> Result<()> {
    let content = fs::read_to_string(&args.template)
        .wrap_err_with(|| format!("failed to read template `{}`", args.template.display()))?;
    let pairs = decrypt_env(&args.file, args.identity.as_deref())?;
    let map: HashMap<String, String> = pairs.into_iter().collect();
    let rendered = render_template(&content, &map).map_err(|missing| {
        eyre!(
            "template references missing credential(s): {} (unit would fail to start)",
            missing.join(", ")
        )
    })?;
    match args.format {
        RenderFormat::Toml => {
            use std::str::FromStr as _;
            toml_edit::DocumentMut::from_str(&rendered).map_err(|err| {
                // `toml_edit` echoes the offending source line, which may
                // contain a substituted secret — report location only.
                let first = err.to_string().lines().next().unwrap_or("parse error").to_string();
                eyre!("rendered output is not valid TOML: {first} (unit would fail to parse it)")
            })?;
        }
        RenderFormat::Json => {
            serde_json::from_str::<serde_json::Value>(&rendered).map_err(|err| {
                eyre!("rendered output is not valid JSON: {err} (unit would fail to parse it)")
            })?;
        }
        RenderFormat::None => {}
    }
    ui.note(&format!(
        "OK: rendered {} ({} bytes, {:?} valid, no values shown)",
        args.template.display(),
        rendered.len(),
        args.format
    ));
    Ok(())
}
