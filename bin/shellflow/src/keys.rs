//! `shellflow keys` — age identity management (generate, public).

use std::path::{Path, PathBuf};

use eyre::{Result, bail, eyre};
use shellflow_secrets::identity::{
    effective_identity_path, generate_identity, load_x25519_identity,
};

use crate::cli::KeysCmd;

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
    // `expand_home` fails closed when `$HOME` is unset, so a `~/…` output path
    // can never degrade into a relative path in the current directory.
    let path = expand_home(output)?;
    if path.exists() {
        bail!("refusing to overwrite existing identity file {}", path.display());
    }
    let identity = generate_identity(&path).map_err(|err| eyre!("{err}"))?;
    println!("wrote identity to {}", path.display());
    println!("public key: {}", identity.to_public());
    Ok(())
}

fn public(identity_path: Option<&Path>) -> Result<()> {
    let path = effective_identity_path(identity_path).map_err(|err| eyre!("{err}"))?;
    let identity =
        load_x25519_identity(&path).map_err(|err| eyre!("{err} (identity: {})", path.display()))?;
    println!("{}", identity.to_public());
    Ok(())
}

/// Expand a leading `~` to the home directory.
///
/// # Errors
///
/// Returns an error when `$HOME` is unset (e.g. in a minimal container), so a
/// `~/…` path never degrades into a relative path.
fn expand_home(path: &Path) -> Result<PathBuf> {
    shellflow_secrets::identity::expand_home(path).map_err(|err| eyre!("{err}"))
}
