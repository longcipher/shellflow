//! `shellflow keys` — age identity management (generate, public).

use std::path::{Path, PathBuf};

use eyre::{Result, bail, eyre};
use shellflow_secrets::identity::{
    effective_identity_path, expand_home, generate_identity, load_x25519_identity,
};

use crate::cli::KeysCmd;

/// Expand a leading `~` to the home directory.
///
/// Returns an error (rather than silently writing to a relative path) when
/// `$HOME` is unset, e.g. in a minimal container.
fn expand_home_strict(path: &Path) -> Result<PathBuf> {
    let expanded = expand_home(path);
    if expanded.to_string_lossy().starts_with("~/") {
        return Err(eyre!("cannot expand `~` in `{}`: $HOME is not set", path.display()));
    }
    Ok(expanded)
}

/// Run a `keys` subcommand.
///
/// # Errors
///
/// Propagates identity I/O and parse errors.
pub(crate) fn run(cmd: &KeysCmd) -> Result<()> {
    match cmd {
        KeysCmd::Generate(args) => generate(&args.output),
        KeysCmd::Public(args) => public(args.identity.as_deref()),
    }
}

fn generate(output: &Path) -> Result<()> {
    let path = expand_home_strict(output)?;
    if path.exists() {
        bail!("refusing to overwrite existing identity file {}", path.display());
    }
    let identity = generate_identity(&path)?;
    println!("wrote identity to {}", path.display());
    println!("public key: {}", identity.to_public());
    Ok(())
}

fn public(identity_path: Option<&Path>) -> Result<()> {
    let path = effective_identity_path(identity_path);
    let identity =
        load_x25519_identity(&path).map_err(|err| eyre!("{err} (identity: {})", path.display()))?;
    println!("{}", identity.to_public());
    Ok(())
}
