//! `shellflow unit render` — the unit generator's command surface.

use std::path::{Path, PathBuf};

use eyre::Result;

use crate::{
    manifest::ServiceManifest,
    unit::{self, DROPIN_NAME},
};

/// The exit code of a failed check (the drop-in is out of date).
const EXIT_OUT_OF_DATE: i32 = 1;

/// Run `shellflow unit …`.
///
/// # Errors
///
/// Returns when the manifest is missing or malformed, when the credential
/// key set cannot be read, or when the drop-in cannot be written.
pub(crate) fn run(cmd: &crate::cli::UnitCmd) -> Result<i32> {
    match cmd {
        crate::cli::UnitCmd::Render(args) => render(args),
        crate::cli::UnitCmd::Manifest(args) => manifest(args),
        crate::cli::UnitCmd::Verify(args) => verify(args),
    }
}

/// Check the repository's consistency.
fn verify(args: &crate::cli::UnitVerifyArgs) -> Result<i32> {
    let report = crate::unit_verify::verify(&args.repo)?;
    for problem in &report.problems {
        eprintln!("error: {problem}");
    }
    if report.problems.is_empty() {
        println!(
            "unit verify: {} unit(s) and {} playbook(s) are consistent",
            report.units, report.playbooks
        );
        return Ok(0);
    }
    eprintln!(
        "unit verify: {} problem(s) in {} unit(s) and {} playbook(s)",
        report.problems.len(),
        report.units,
        report.playbooks
    );
    Ok(crate::unit_verify::EXIT_OUT_OF_DATE)
}

/// Generate a service's drop-in.
fn render(args: &crate::cli::UnitRenderArgs) -> Result<i32> {
    let repo = &args.repo;
    let manifest = ServiceManifest::load(repo, &args.service, &args.unit)?;

    // The credential key set: the sealed file's keys, never its values.
    let keys = if manifest.secret_file.is_some() {
        let file = manifest.credential_file().map_err(|err| eyre::eyre!("{err}"))?;
        let path = repo.join(&file);
        crate::secret::credential_key_set(&path, args.identity.as_deref()).map_err(|err| {
            eyre::eyre!("cannot read the credential keys of `{}`: {err}", path.display())
        })?
    } else {
        Vec::new()
    };

    let rendered = unit::render(&manifest, &keys);
    let target =
        args.output.clone().unwrap_or_else(|| unit::dropin_path(repo, &args.service, &args.unit));

    if args.stdout {
        print!("{}", rendered.text);
        return Ok(0);
    }

    if args.check {
        let current = std::fs::read_to_string(&target).unwrap_or_default();
        if current == rendered.text {
            println!("{} is up to date", target.display());
            return Ok(0);
        }
        eprintln!(
            "error: {} is out of date: run `shellflow unit render {}`",
            target.display(),
            args.service
        );
        return Ok(EXIT_OUT_OF_DATE);
    }

    write_dropin(&target, &rendered.text)?;
    println!("==> wrote {}", target.display());
    Ok(0)
}

/// Print a service's manifest.
fn manifest(args: &crate::cli::UnitManifestArgs) -> Result<i32> {
    let manifest = ServiceManifest::load(&args.repo, &args.service, &args.unit)?;
    println!("service      = {}", manifest.service);
    println!("host         = {}", manifest.host);
    println!("unit         = {}", manifest.unit);
    if let Some(binary) = &manifest.binary {
        println!("binary       = {binary}");
    }
    if let Some(file) = &manifest.secret_file {
        println!("secret_file  = {file}");
    }
    if let Some(store) = &manifest.store {
        println!("store        = {store}");
    }
    if !manifest.credentials.is_empty() {
        println!("credentials  = {}", manifest.credentials.join(", "));
    }
    for (template, target) in &manifest.renders {
        println!("render       = {template} -> {target}");
    }
    if !manifest.ports.is_empty() {
        println!(
            "ports        = {}",
            manifest.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
        );
    }
    if let Some(health) = &manifest.health {
        println!("health       = {health}");
    }
    if let Some(user) = &manifest.user {
        println!("user         = {user}");
    }
    if let Some(dir) = &manifest.runtime_dir {
        println!("runtime_dir  = {dir}");
    }
    Ok(0)
}

/// Write the drop-in atomically.
///
/// The drop-in is a live systemd file: a reader must never observe a
/// half-written one, so the text is written beside the destination and
/// renamed into place.
fn write_dropin(target: &Path, text: &str) -> Result<()> {
    let parent =
        target.parent().ok_or_else(|| eyre::eyre!("`{}` has no parent", target.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|err| eyre::eyre!("cannot create `{}`: {err}", parent.display()))?;
    let tmp: PathBuf = parent.join(format!(".{DROPIN_NAME}.shellflow-new"));
    std::fs::write(&tmp, text)
        .map_err(|err| eyre::eyre!("cannot write `{}`: {err}", tmp.display()))?;
    std::fs::rename(&tmp, target)
        .map_err(|err| eyre::eyre!("cannot install `{}`: {err}", target.display()))?;
    Ok(())
}
