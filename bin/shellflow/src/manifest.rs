//! The service manifest: the facts about a service that the tooling needs.
//!
//! A deploy repository repeats the same facts in three places: the systemd
//! unit, the playbook, and — implicitly — the operator's memory. The unit
//! declares the credential keys, the render template, and the binary; the
//! playbook repeats the service name and the host. A manifest states them
//! **once**, and the tooling derives the rest:
//!
//! * `shellflow unit render` generates the credential wiring, the render line, and the version
//!   status line as a drop-in;
//! * `shellflow service status --all` reads the fleet map from the manifests instead of parsing
//!   playbook text;
//! * `shellflow service check --all` audits every service of a host in one round trip.
//!
//! The manifest lives at `services/<svc>/service.toml`:
//!
//! ```toml
//! host = "api"
//! unit = "dufs.service"
//! binary = "/opt/dufs/bin/dufs"
//! secret_file = "services/dufs/{host}.env.age"
//!
//! [render]
//! template = "/opt/dufs/etc/config.yaml.tmpl"
//! target = "/run/dufs/config.yaml"
//! ```

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
};

/// The credential store root, as the `cred-env` helper uses it.
pub(crate) const CREDSTORE_ROOT: &str = "/etc/credstore.encrypted";

/// The suffix of a manifest file inside a service directory.
///
/// The manifest is **per unit**: a service may own several units (the
/// longtrader strategies, the cidx indexers), and each of them renders its
/// own configuration from its own template.
pub(crate) const MANIFEST_SUFFIX: &str = ".service.toml";

/// A manifest that could not be read or understood.
#[derive(Debug)]
pub(crate) struct ManifestError {
    pub(crate) message: String,
}

impl ManifestError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ManifestError {}

/// The facts about one service.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ServiceManifest {
    /// The service name (the directory name under `services/`).
    pub service: String,
    /// The host alias the service runs on.
    pub host: String,
    /// The systemd unit name.
    pub unit: String,
    /// The binary the unit runs (for the version status line).
    pub binary: Option<String>,
    /// The sealed credential file; `{host}` is the host alias.
    pub secret_file: Option<String>,
    /// The credential store directory (default: the service name).
    ///
    /// A service that shares a store with a sibling declares it: the store
    /// name is what the `LoadCredentialEncrypted=` paths point at.
    pub store: Option<String>,
    /// The credential keys the unit declares.
    ///
    /// Empty means "every key in the sealed file"; a list narrows it, for a
    /// unit that must see only part of a shared store.
    pub credentials: Vec<String>,
    /// The configuration templates the unit renders, and where each lands.
    ///
    /// A unit may render more than one file: the ledgerflow unit renders a
    /// master key and a configuration.
    pub renders: Vec<(String, String)>,
    /// The ports the service listens on.
    pub ports: Vec<u16>,
    /// The URL the service answers on.
    pub health: Option<String>,
    /// The user the unit runs as.
    pub user: Option<String>,
    /// The runtime directory the unit owns.
    pub runtime_dir: Option<String>,
    /// Whether the unit gets the shared hardening drop-in.
    ///
    /// `true` by default: the hardening is a default, not an opt-in. A unit
    /// that cannot take it — one that needs `/home` visible, say — says so
    /// here, and the check stops asking for it.
    pub hardening: bool,
}

impl ServiceManifest {
    /// Parse a manifest from its TOML text.
    ///
    /// The `service` name is taken from the file's own directory, so the text
    /// itself never has to repeat it.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the text is not valid TOML, when a
    /// required key is missing, or when a key has the wrong shape.
    pub(crate) fn parse(service: &str, text: &str) -> Result<Self, ManifestError> {
        let doc: toml_edit::DocumentMut =
            text.parse().map_err(|err| ManifestError::new(format!("invalid TOML: {err}")))?;

        let host = require_str(&doc, "host", service)?;
        let unit = require_str(&doc, "unit", service)?;

        // `[[render]]` is an array of tables: one entry per rendered file.
        let renders = match doc.get("render") {
            None => Vec::new(),
            Some(item) => {
                let mut renders = Vec::new();
                if let Some(array) = item.as_array_of_tables() {
                    for table in array {
                        renders.push((
                            require_str_in(table, "template", service, "render")?,
                            require_str_in(table, "target", service, "render")?,
                        ));
                    }
                } else if let Some(table) = item.as_table() {
                    renders.push((
                        require_str_in(table, "template", service, "render")?,
                        require_str_in(table, "target", service, "render")?,
                    ));
                } else {
                    return Err(ManifestError::new(
                        "`[[render]]` must be a table or an array of tables",
                    ));
                }
                renders
            }
        };

        let manifest = Self {
            service: service.to_string(),
            host,
            unit,
            binary: optional_str(&doc, "binary", service)?,
            secret_file: optional_str(&doc, "secret_file", service)?,
            store: optional_str(&doc, "store", service)?,
            credentials: optional_str_list(&doc, "credentials", service)?,
            renders,
            ports: optional_ports(&doc, service)?,
            health: optional_str(&doc, "health", service)?,
            user: optional_str(&doc, "user", service)?,
            runtime_dir: optional_str(&doc, "runtime_dir", service)?,
            hardening: optional_bool(&doc, "hardening", service)?,
        };
        Ok(manifest)
    }

    /// Read the manifest of one unit from a repository.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the file is missing or malformed.
    pub(crate) fn load(repo: &Path, service: &str, unit: &str) -> Result<Self, ManifestError> {
        let path = manifest_path(repo, service, unit);
        let text = std::fs::read_to_string(&path).map_err(|err| {
            ManifestError::new(format!("cannot read `{}`: {err}", path.display()))
        })?;
        let mut manifest = Self::parse(service, &text)?;
        manifest.unit = unit.to_string();
        Ok(manifest)
    }

    /// The credential keys the service declares, read from the manifest.
    ///
    /// The manifest names the *file*; the keys live in the sealed env file,
    /// and only the age identity can list them.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError`] when the manifest names no credential file.
    pub(crate) fn credential_file(&self) -> Result<String, ManifestError> {
        self.secret_file.as_ref().map(|file| file.replace("{host}", &self.host)).ok_or_else(|| {
            ManifestError::new(format!(
                "the manifest of `{}` declares no `secret_file`",
                self.service
            ))
        })
    }

    /// The credential store directory of the service.
    #[must_use]
    pub(crate) fn store_dir(&self) -> PathBuf {
        Path::new(CREDSTORE_ROOT).join(self.store.as_deref().unwrap_or(&self.service))
    }
}

/// The path of a unit's manifest inside a repository.
#[must_use]
pub(crate) fn manifest_path(repo: &Path, service: &str, unit: &str) -> PathBuf {
    repo.join("services").join(service).join(format!("{unit}{MANIFEST_SUFFIX}"))
}

/// Every manifest of a repository, keyed by `<service>/<unit>`.
///
/// A repository without manifests yields an empty map: the callers fall back
/// to whatever they used before.
pub(crate) fn load_all(repo: &Path) -> Result<BTreeMap<String, ServiceManifest>, ManifestError> {
    let services = repo.join("services");
    let Ok(entries) = std::fs::read_dir(&services) else {
        return Ok(BTreeMap::new());
    };
    let mut manifests = BTreeMap::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Ok(units) = std::fs::read_dir(&path) else {
            continue;
        };
        for unit_entry in units.flatten() {
            let unit_path = unit_entry.path();
            if unit_path.extension().is_none_or(|ext| ext != "toml") {
                continue;
            }
            let Some(file) = unit_path.file_stem().and_then(|n| n.to_str()) else {
                continue;
            };
            let Some(unit) = file.strip_suffix(".service") else {
                continue;
            };
            let manifest = ServiceManifest::load(repo, name, unit)?;
            manifests.insert(format!("{name}/{unit}"), manifest);
        }
    }
    Ok(manifests)
}

/// The service-to-host map of a repository, from the manifests.
///
/// The units of a service must agree on the host: a service that runs on two
/// hosts is two services, not one.
pub(crate) fn service_fleet(
    manifests: &BTreeMap<String, ServiceManifest>,
) -> Result<BTreeMap<String, Vec<String>>, ManifestError> {
    let mut hosts: BTreeMap<String, String> = BTreeMap::new();
    for manifest in manifests.values() {
        match hosts.get(&manifest.service) {
            Some(host) if host != &manifest.host => {
                return Err(ManifestError::new(format!(
                    "the units of `{}` disagree on the host: `{host}` and `{}`",
                    manifest.service, manifest.host
                )));
            }
            _ => {
                hosts.insert(manifest.service.clone(), manifest.host.clone());
            }
        }
    }
    let mut fleet: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (service, host) in hosts {
        fleet.entry(host).or_default().push(service);
    }
    Ok(fleet)
}

/// A required string key.
fn require_str(
    doc: &toml_edit::DocumentMut,
    key: &str,
    service: &str,
) -> Result<String, ManifestError> {
    doc.get(key).and_then(toml_edit::Item::as_str).map(ToOwned::to_owned).ok_or_else(|| {
        ManifestError::new(format!("the manifest of `{service}` has no `{key}` string"))
    })
}

/// A required string key of a sub-table.
fn require_str_in(
    table: &toml_edit::Table,
    key: &str,
    service: &str,
    section: &str,
) -> Result<String, ManifestError> {
    table.get(key).and_then(toml_edit::Item::as_str).map(ToOwned::to_owned).ok_or_else(|| {
        ManifestError::new(format!("the manifest of `{service}` has no `{section}.{key}` string"))
    })
}

/// An optional string key.
fn optional_str(
    doc: &toml_edit::DocumentMut,
    key: &str,
    service: &str,
) -> Result<Option<String>, ManifestError> {
    match doc.get(key) {
        None => Ok(None),
        Some(item) => item.as_str().map(|value| Some(value.to_string())).ok_or_else(|| {
            ManifestError::new(format!("the manifest of `{service}` has a non-string `{key}`"))
        }),
    }
}

/// An optional boolean key.
fn optional_bool(
    doc: &toml_edit::DocumentMut,
    key: &str,
    service: &str,
) -> Result<bool, ManifestError> {
    match doc.get(key) {
        None => Ok(true),
        Some(item) => item.as_bool().ok_or_else(|| {
            ManifestError::new(format!("the manifest of `{service}` has a non-boolean `{key}`"))
        }),
    }
}

/// An optional list of strings.
fn optional_str_list(
    doc: &toml_edit::DocumentMut,
    key: &str,
    service: &str,
) -> Result<Vec<String>, ManifestError> {
    let Some(item) = doc.get(key) else {
        return Ok(Vec::new());
    };
    let Some(array) = item.as_array() else {
        return Err(ManifestError::new(format!(
            "the manifest of `{service}` has a non-list `{key}`"
        )));
    };
    let mut values = Vec::with_capacity(array.len());
    for value in array {
        let text = value.as_str().ok_or_else(|| {
            ManifestError::new(format!(
                "the manifest of `{service}` has a non-string `{key}` entry"
            ))
        })?;
        values.push(text.to_string());
    }
    Ok(values)
}

/// An optional list of ports.
fn optional_ports(doc: &toml_edit::DocumentMut, service: &str) -> Result<Vec<u16>, ManifestError> {
    let Some(item) = doc.get("ports") else {
        return Ok(Vec::new());
    };
    let Some(array) = item.as_array() else {
        return Err(ManifestError::new(format!(
            "the manifest of `{service}` has a non-list `ports`"
        )));
    };
    let mut ports = Vec::with_capacity(array.len());
    for value in array {
        let port = value.as_integer().ok_or_else(|| {
            ManifestError::new(format!("the manifest of `{service}` has a non-integer port"))
        })?;
        let port = u16::try_from(port).map_err(|_| {
            ManifestError::new(format!("the manifest of `{service}` has an out-of-range port"))
        })?;
        if port == 0 {
            return Err(ManifestError::new(format!(
                "the manifest of `{service}` has port 0, which is not a listening port"
            )));
        }
        ports.push(port);
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{ServiceManifest, load_all};

    #[test]
    fn a_minimal_manifest_parses() {
        let manifest = ServiceManifest::parse("dufs", "host = \"api\"\nunit = \"dufs.service\"\n")
            .expect("manifest");
        assert_eq!(manifest.service, "dufs");
        assert_eq!(manifest.host, "api");
        assert_eq!(manifest.unit, "dufs.service");
        assert!(manifest.binary.is_none());
        assert!(manifest.renders.is_empty());
    }

    #[test]
    fn a_full_manifest_parses() {
        let manifest = ServiceManifest::parse(
            "dufs",
            "host = \"api\"\n\
             unit = \"dufs.service\"\n\
             binary = \"/opt/dufs/bin/dufs\"\n\
             secret_file = \"services/dufs/{host}.env.age\"\n\
             ports = [5000, 5001]\n\
             health = \"http://127.0.0.1:5000/\"\n\
             user = \"akagi201\"\n\
             runtime_dir = \"dufs\"\n\
             \n\
             [render]\n\
             template = \"/opt/dufs/etc/config.yaml.tmpl\"\n\
             target = \"/run/dufs/config.yaml\"\n",
        )
        .expect("manifest");
        assert_eq!(manifest.binary.as_deref(), Some("/opt/dufs/bin/dufs"));
        assert_eq!(manifest.ports, vec![5000, 5001]);
        assert_eq!(manifest.user.as_deref(), Some("akagi201"));
        assert_eq!(
            manifest.renders,
            vec![(
                "/opt/dufs/etc/config.yaml.tmpl".to_string(),
                "/run/dufs/config.yaml".to_string()
            )]
        );
    }

    #[test]
    fn a_manifest_without_a_host_is_rejected() {
        let err = ServiceManifest::parse("dufs", "unit = \"dufs.service\"\n").unwrap_err();
        assert!(err.to_string().contains("no `host` string"), "{err}");
    }

    #[test]
    fn a_manifest_without_a_unit_is_rejected() {
        let err = ServiceManifest::parse("dufs", "host = \"api\"\n").unwrap_err();
        assert!(err.to_string().contains("no `unit` string"), "{err}");
    }

    #[test]
    fn a_unit_may_render_several_files() {
        let manifest = ServiceManifest::parse(
            "ledgerflow-cloud",
            "host = \"api\"\nunit = \"ledgerflow-cloud.service\"\n\
             [[render]]\ntemplate = \"/a.tmpl\"\ntarget = \"/run/a\"\n\
             [[render]]\ntemplate = \"/b.tmpl\"\ntarget = \"/run/b\"\n",
        )
        .expect("manifest");
        assert_eq!(manifest.renders.len(), 2);
        assert_eq!(manifest.renders[1].1, "/run/b");
    }

    #[test]
    fn a_render_section_without_a_target_is_rejected() {
        let err = ServiceManifest::parse(
            "dufs",
            "host = \"api\"\nunit = \"dufs.service\"\n\
             [render]\ntemplate = \"/t\"\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("no `render.target` string"), "{err}");
    }

    #[test]
    fn a_port_out_of_range_is_rejected() {
        let err = ServiceManifest::parse(
            "dufs",
            "host = \"api\"\nunit = \"dufs.service\"\nports = [70000]\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("out-of-range port"), "{err}");
    }

    #[test]
    fn a_port_zero_is_rejected() {
        let err = ServiceManifest::parse(
            "dufs",
            "host = \"api\"\nunit = \"dufs.service\"\nports = [0]\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("port 0"), "{err}");
    }

    #[test]
    fn the_credential_file_resolves_the_host_placeholder() {
        let manifest = ServiceManifest::parse(
            "dufs",
            "host = \"api\"\nunit = \"dufs.service\"\n\
             secret_file = \"services/dufs/{host}.env.age\"\n",
        )
        .expect("manifest");
        assert_eq!(manifest.credential_file().expect("file"), "services/dufs/api.env.age");
    }

    #[test]
    fn a_manifest_can_name_a_shared_store_and_a_key_subset() {
        let manifest = ServiceManifest::parse(
            "longtrader-api",
            "host = \"api\"\nunit = \"longtrader.service\"\n\
             store = \"longtrader\"\n\
             credentials = [\"CFG_HTX_API_KEY\"]\n",
        )
        .expect("manifest");
        assert_eq!(manifest.credentials, vec!["CFG_HTX_API_KEY".to_string()]);
        assert_eq!(
            manifest.store_dir().display().to_string(),
            "/etc/credstore.encrypted/longtrader"
        );
    }

    #[test]
    fn a_manifest_without_a_store_uses_the_service_name() {
        let manifest = ServiceManifest::parse("dufs", "host = \"api\"\nunit = \"dufs.service\"\n")
            .expect("manifest");
        assert_eq!(manifest.store_dir().display().to_string(), "/etc/credstore.encrypted/dufs");
    }

    #[test]
    fn the_fleet_maps_a_host_to_its_services() {
        let dir = tempfile::tempdir().expect("tempdir");
        for (service, unit, host) in
            [("dufs", "dufs", "api"), ("rpxy", "rpxy", "api"), ("sws", "sws", "trade")]
        {
            let path = dir.path().join("services").join(service);
            fs::create_dir_all(&path).expect("mkdir");
            fs::write(
                path.join(format!("{unit}.service.toml")),
                format!("host = \"{host}\"\nunit = \"{unit}.service\"\n"),
            )
            .expect("write");
        }
        let manifests = load_all(dir.path()).expect("load");
        let fleet = super::service_fleet(&manifests).expect("fleet");
        assert_eq!(fleet["api"], vec!["dufs".to_string(), "rpxy".to_string()]);
        assert_eq!(fleet["trade"], vec!["sws".to_string()]);
    }

    #[test]
    fn the_units_of_a_service_must_agree_on_the_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("services").join("longtrader");
        fs::create_dir_all(&path).expect("mkdir");
        fs::write(path.join("a.service.toml"), "host = \"api\"\nunit = \"a.service\"\n")
            .expect("write");
        fs::write(path.join("b.service.toml"), "host = \"trade\"\nunit = \"b.service\"\n")
            .expect("write");
        let manifests = load_all(dir.path()).expect("load");
        let err = super::service_fleet(&manifests).unwrap_err();
        assert!(err.to_string().contains("disagree on the host"), "{err}");
    }

    #[test]
    fn a_repository_without_manifests_yields_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let manifests = load_all(dir.path()).expect("load");
        assert!(manifests.is_empty());
    }

    #[test]
    fn a_repository_is_scanned_for_manifests() {
        let dir = tempfile::tempdir().expect("tempdir");
        let service = dir.path().join("services").join("dufs");
        fs::create_dir_all(&service).expect("mkdir");
        fs::write(service.join("dufs.service.toml"), "host = \"api\"\nunit = \"dufs.service\"\n")
            .expect("write");
        // A directory without a manifest is not a service.
        fs::create_dir_all(dir.path().join("services").join("_common")).expect("mkdir");
        let manifests = load_all(dir.path()).expect("load");
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests["dufs/dufs"].host, "api");
        assert_eq!(manifests["dufs/dufs"].unit, "dufs");
    }
}
