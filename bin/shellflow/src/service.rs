//! `shellflow service init` — scaffold a new service in the flat layout.
//!
//! Generates the three files a new service needs in the current repository:
//!
//! ```text
//! services/<svc>/<svc>.json5.tmpl   # plaintext config template (${KEY} placeholders)
//! services/<svc>/<svc>.service      # systemd unit (shared cred-env helper)
//! playbooks/deploy-<svc>.sh         # deploy playbook skeleton
//! ```
//!
//! The generated content encodes the documented convention (see SKILL.md
//! §4.1): flat service directory, per-host encrypted env, per-service
//! credential store, shared hardening drop-in, and the shared target-side
//! `cred-env` helper instead of a per-service starter script.

use std::{
    fs,
    path::{Path, PathBuf},
};

use eyre::{Context, Result, bail};

use crate::cli::{ServiceCmd, ServiceInitArgs};

/// Scaffold a service.
///
/// # Errors
///
/// Returns when the service name is unusable, when any target path already
/// exists (never overwrites), or on I/O failures.
pub(crate) fn run(cmd: &ServiceCmd) -> Result<()> {
    match cmd {
        ServiceCmd::Init(args) => init(args),
    }
}

/// Scaffold a service (`service init`).
///
/// # Errors
///
/// Returns when the service name is unusable, when any target path already
/// exists (never overwrites), or on I/O failures.
/// The config template (token `__SVC__`).
const CONFIG_TEMPLATE: &str = r#"{
  // __SVC__ 配置模板 — `shellflow cred-env render` 在 unit 启动时把加密 env
  // 中的键值注入下方占位符 (占位符形如: 美元符号 + 花括号 + 键名 + 右花括号):
  //   /usr/local/bin/shellflow cred-env render \
  //     /etc/__SVC__/__SVC__.json5.tmpl /run/__SVC__/__SVC__.json5
  // 值来自加密 env (逐主机), 渲染产物 0600, unit 退出即毁。
  // 自检: shellflow template check services/__SVC__/__SVC__.json5.tmpl \
  //         services/__SVC__/<host>.env.age
  // 注意: 注释里不要写占位符文本, 会被当作真实占位符校验。
  //
  // TODO: 按应用配置格式改写下面内容; 不需要配置文件的应用删掉本模板与
  //       unit 里的 ExecStartPre= 行。
  mode: "default",
  listen: { endpoints: ["${LISTEN_ENDPOINT}"] },
}
"#;

/// The systemd unit (token `__SVC__`).
const UNIT_TEMPLATE: &str = r"[Unit]
Description=__SVC__ (encrypted credentials via systemd-creds)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
# 专用运行用户 (playbook 自动创建, 最小权限)
User=__SVC__
Group=__SVC__

# tmpfs 目录: 渲染产物落这里 (0700, unit 退出即毁)
RuntimeDirectory=__SVC__
RuntimeDirectoryMode=0700

# 需要配置文件的第三方应用: 渲染明文模板 (无密值) 进 tmpfs; 不需要则删掉本行
ExecStartPre=/usr/local/bin/shellflow cred-env render /etc/__SVC__/__SVC__.json5.tmpl /run/__SVC__/__SVC__.json5

# 共享助手 (playbook 安装到 /usr/local/bin/shellflow, 全服务共用, 无每服务
# 启动器): 导出 systemd 凭据为环境变量后 exec 真实二进制。
# 自研应用可改为 ExecStart 直接指二进制, 启动早期读 $CREDENTIALS_DIRECTORY。
ExecStart=/usr/local/bin/shellflow cred-env exec /opt/__SVC__/bin/__SVC__

# ★ 逐键从按服务 credstore 导入 (重新生成本段):
#   shellflow secret creds --store-dir /etc/credstore.encrypted/__SVC__ \
#     services/__SVC__/<host>.env.age
# 粘贴输出的 LoadCredentialEncrypted= 行到下面 (各主机键集合必须一致):
# LoadCredentialEncrypted=API_KEY:/etc/credstore.encrypted/__SVC__/API_KEY

# --- 安全加固见 services/_common/10-hardening.conf ---
# playbook 安装为 /etc/systemd/system/__SVC__.service.d/10-hardening.conf

[Install]
WantedBy=multi-user.target
";

/// The deploy playbook (tokens `__SVC__`, `__SERVER_LINES__`, `__HOST__`).
const PLAYBOOK_TEMPLATE: &str = r#"#!/usr/bin/env shellflow

# ============================================================
# shellflow playbook: 部署/升级 __SVC__
# ============================================================
# 布局: services/__SVC__/ 扁平化; 凭据->env 与模板渲染走共享 cred-env 助手
#   (同一 shellflow 二进制, playbook 安装到 /usr/local/bin/shellflow)。
#
# 用法:
#   shellflow -k playbooks/deploy-__SVC__.sh
#   shellflow --dry-run --diff playbooks/deploy-__SVC__.sh
#   shellflow playbooks/deploy-__SVC__.sh

# === 服务器 (声明本服务实际部署的主机; 缺文件的 host 会 fail-closed) ===
__SERVER_LINES__
# === 敏感信息: age 加密 env, {host} 按目标机别名解析 ===
# @secrets services/__SVC__/{host}.env.age

# === 1. Local: 获取产物 (下载 release 并校验 sha256 / 本地构建) ===
# @name fetch
# @local
set -eu
SVC=__SVC__
# 目标机助手: 同一 shellflow 二进制提供 cred-env exec/render/credstore-install。
# musl 静态 (zigbuild), 无 glibc 耦合; 目标机只需这一个二进制。
TARGET_ARCH="${TARGET_ARCH:-x86_64-unknown-linux-musl}"
SHELLFLOW_SRC="${SHELLFLOW_SRC:-$HOME/src/github.com/longcipher/shellflow}"
[ -d "${SHELLFLOW_SRC}" ] || { echo "!! SHELLFLOW_SRC not found: ${SHELLFLOW_SRC}" >&2; exit 1; }
STAMP="${SVC}-$(date +%s)"
WORKDIR="/tmp/${STAMP}"
mkdir -p "${WORKDIR}"
# TODO: 下载/构建产物到 ${WORKDIR} (示例见 infra 仓库 playbooks/deploy-zenoh.sh)
( cd "${SHELLFLOW_SRC}" && cargo zigbuild --release -p shellflow --target "${TARGET_ARCH}" )
cp "${SHELLFLOW_SRC}/target/${TARGET_ARCH}/release/shellflow" "${WORKDIR}/shellflow"
# @export STAMP,WORKDIR,SVC

# === 2. Copy: 整目录下发 (age 密文不下发 — @secrets 走 payload 注入) ===
# @name ship-artifacts
# @copy $WORKDIR/<artifact-dir> -> $WORKDIR/<artifact-dir> @__HOST__
# @copy services/$SVC -> $WORKDIR/svc @__HOST__ --exclude *.age
# @copy services/_common/10-hardening.conf -> $WORKDIR/10-hardening.conf @__HOST__
# @copy $WORKDIR/shellflow -> $WORKDIR/shellflow @__HOST__

# === 3. Remote: 安装 + host-key 绑定凭据 ===
# @name install
# @remote __HOST__
# @timeout 180
set -eu
echo "==> installing ${SVC} on $(hostname)"
sudo id "${SVC}" >/dev/null 2>&1 || sudo useradd --system --home-dir "/etc/${SVC}" --shell /usr/sbin/nologin "${SVC}"
sudo install -d -m 0755 /usr/local/lib/"${SVC}"
sudo install -d -m 0755 "/opt/${SVC}/bin"
sudo install -d -m 0755 "/etc/${SVC}"
sudo install -d -m 0755 /usr/local/bin
# TODO: 安装产物 (二进制/插件), 示例见 infra 仓库 playbooks/deploy-zenoh.sh
# 明文配置模板 (无密值; 渲染产物在 unit 启动时进 tmpfs)
sudo install -m 0644 "${WORKDIR}/svc/${SVC}.json5.tmpl" "/etc/${SVC}/${SVC}.json5.tmpl"
# 共享 cred-env 助手 (同一 shellflow 二进制; 幂等升级)
sudo install -m 0755 "${WORKDIR}/shellflow" /usr/local/bin/shellflow
sudo install -m 0644 "${WORKDIR}/svc/${SVC}.service" "/etc/systemd/system/${SVC}.service"
sudo install -d -m 0755 "/etc/systemd/system/${SVC}.service.d"
sudo install -m 0644 "${WORKDIR}/10-hardening.conf" "/etc/systemd/system/${SVC}.service.d/10-hardening.conf"
# 凭据: 每服务子目录 + 逐键 host-key 绑定 (Rust 子命令; 值走 stdin 不进 argv;
# 与目标机登录 shell 是 bash 还是 zsh 无关)
/usr/local/bin/shellflow cred-env credstore-install "${SVC}"
rm -rf "${WORKDIR}/svc" "${WORKDIR}/10-hardening.conf" "${WORKDIR}/shellflow"

# === 4. Remote: enable + restart ===
# @name enable-start
# @remote __HOST__
set -eu
sudo systemctl daemon-reload
sudo systemctl enable "${SVC}.service"
sudo systemctl restart "${SVC}.service"
sudo systemctl is-active "${SVC}.service"

# === 5. Remote: 验证 ===
# @name verify
# @remote __HOST__
set -eu
echo "==> ${SVC} status: $(sudo systemctl is-active "${SVC}.service")"
sudo ls -l "/etc/credstore.encrypted/${SVC}/"
sudo ls -l "/run/credentials/${SVC}.service/" 2>/dev/null || true
sudo journalctl -u "${SVC}.service" --no-pager -n 15
"#;

/// Scaffold a service (`service init`).
///
/// # Errors
///
/// Returns when the service name is unusable, when any target path already
/// exists (never overwrites), or on I/O failures.
fn init(cmd: &ServiceInitArgs) -> Result<()> {
    let service = cmd.service.trim();
    let hosts: Vec<String> = if cmd.hosts.is_empty() {
        vec!["api".to_string()]
    } else {
        cmd.hosts.iter().map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect()
    };
    validate_service_name(service)?;
    if hosts.is_empty() {
        bail!("no hosts given: pass `--host <alias>` with a non-empty value");
    }

    let dir = PathBuf::from(format!("services/{service}"));
    let playbook = PathBuf::from(format!("playbooks/deploy-{service}.sh"));
    let config = dir.join(format!("{service}.json5.tmpl"));
    let unit = dir.join(format!("{service}.service"));
    for path in [&config, &unit, &playbook] {
        if path.exists() {
            bail!("refusing to overwrite existing `{}`", path.display());
        }
    }

    fs::create_dir_all(&dir).wrap_err_with(|| format!("failed to create `{}`", dir.display()))?;
    write_file(&config, &render(CONFIG_TEMPLATE, service))?;
    write_file(&unit, &render(UNIT_TEMPLATE, service))?;

    let server_lines =
        hosts.iter().map(|h| format!("# @server {h:<8} {h}")).collect::<Vec<_>>().join("\n");
    let playbook_body = PLAYBOOK_TEMPLATE
        .replace("__SERVER_LINES__", server_lines.trim_end())
        .replace("__HOST__", &hosts[0])
        .replace("__SVC__", service);
    write_executable(&playbook, &playbook_body)?;

    println!("==> scaffolded:");
    println!("    {}   (plaintext template, placeholder syntax)", config.display());
    println!("    {}      (ExecStart via the shared cred-env helper)", unit.display());
    println!("    {}", playbook.display());
    println!("==> next: create the encrypted env (one per host, same key set):");
    for host in &hosts {
        println!("    {{ printf 'KEY=...\\n'; }} | shellflow secret encrypt \\");
        println!("      -r \"$(cat keys/recipients/*.pub)\" \\");
        println!("      -o services/{service}/{host}.env.age");
    }
    println!("==> then:");
    println!("    1) shellflow secret keys-check services/{service}");
    println!("    2) shellflow template check services/{service}/{service}.json5.tmpl \\");
    println!("         services/{service}/{}.env.age", hosts[0]);
    println!("    3) shellflow secret creds --store-dir /etc/credstore.encrypted/{service} \\");
    println!(
        "         services/{service}/{}.env.age   # paste LoadCredentialEncrypted= lines",
        hosts[0]
    );
    Ok(())
}

/// Validate the service name: it becomes a directory and a path component.
fn validate_service_name(service: &str) -> Result<()> {
    let valid = !service.is_empty() &&
        service.starts_with(|c: char| c.is_ascii_lowercase()) &&
        service.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') &&
        !service.contains("--");
    if !valid {
        bail!("invalid service name `{service}` (want [a-z][a-z0-9-]*)");
    }
    Ok(())
}

/// Replace the `__SVC__` token (used instead of `format!` so template braces
/// and `$`-sigils stay literal).
fn render(template: &str, service: &str) -> String {
    template.replace("__SVC__", service)
}

/// Write a file, creating parent directories.
fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed to create `{}`", parent.display()))?;
    }
    fs::write(path, content).wrap_err_with(|| format!("failed to write `{}`", path.display()))
}

/// Write a file with mode 0755 (playbooks are executed directly).
fn write_executable(path: &Path, content: &str) -> Result<()> {
    write_file(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .wrap_err_with(|| format!("failed to chmod `{}`", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CONFIG_TEMPLATE, PLAYBOOK_TEMPLATE, UNIT_TEMPLATE, render, validate_service_name};

    #[test]
    fn render_replaces_every_token() {
        let unit = render(UNIT_TEMPLATE, "myapp");
        assert!(!unit.contains("__SVC__"));
        assert!(unit.contains("User=myapp"));
        assert!(unit.contains("/etc/myapp/myapp.json5.tmpl"));
        assert!(
            unit.contains("ExecStart=/usr/local/bin/shellflow cred-env exec /opt/myapp/bin/myapp")
        );
    }

    #[test]
    fn generated_unit_targets_the_shared_helper() {
        let unit = render(UNIT_TEMPLATE, "zenoh");
        assert!(unit.contains("cred-env render"));
        assert!(unit.contains("cred-env exec"));
        assert!(!unit.contains("zenoh-start"), "no per-service starter script");
    }

    #[test]
    fn generated_template_uses_real_placeholders() {
        let config = render(CONFIG_TEMPLATE, "myapp");
        assert!(!config.contains("__SVC__"));
        // The scaffold must ship a resolvable `${KEY}` placeholder, not a
        // leftover token (which `template check` would silently ignore).
        assert!(!config.contains("__LISTEN_ENDPOINT__"));
        assert_eq!(
            shellflow_core::template_keys(&config),
            vec!["LISTEN_ENDPOINT"],
            "scaffold template references exactly LISTEN_ENDPOINT"
        );
    }

    #[test]
    fn playbook_template_keeps_directives_and_drops_tokens() {
        let body = PLAYBOOK_TEMPLATE
            .replace("__SERVER_LINES__", "# @server api      api")
            .replace("__HOST__", "api")
            .replace("__SVC__", "myapp");
        assert!(!body.contains("__SVC__"));
        assert!(!body.contains("__HOST__"));
        assert!(body.contains("# @server api      api"));
        assert!(body.contains("# @secrets services/myapp/{host}.env.age"));
        assert!(body.contains("cred-env credstore-install"));
        assert!(body.contains("cargo zigbuild"));
        // No line may open with a bare directive token: comment lines that
        // start (after `#` + whitespace) with `@` are parsed as directives.
        for line in body.lines() {
            let trimmed = line.trim_start();
            if let Some(rest) = trimmed.strip_prefix('#') {
                assert!(
                    !rest.trim_start().starts_with('@') || line.starts_with("# @"),
                    "stray directive-looking comment: {line}"
                );
            }
        }
    }

    #[test]
    fn service_name_validation() {
        assert!(validate_service_name("api").is_ok());
        assert!(validate_service_name("secret-app").is_ok());
        assert!(validate_service_name("zenoh").is_ok());
        assert!(validate_service_name("").is_err());
        assert!(validate_service_name("Api").is_err());
        assert!(validate_service_name("../etc").is_err());
        assert!(validate_service_name("a b").is_err());
        assert!(validate_service_name("a/b").is_err());
    }
}
