//! `shellflow keys` — age identity management (generate, public).

use std::path::{Path, PathBuf};

use eyre::{Result, bail, eyre};
use shellflow_secrets::identity::{
    effective_identity_path, generate_identity, load_x25519_identity,
};

use crate::cli::KeysCmd;

/// Expand a leading `~` to the home directory.
fn expand_home(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rest)
    } else {
        path.to_path_buf()
    }
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
    let path = expand_home(output);
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
