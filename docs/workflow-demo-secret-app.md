# Demo Secret App — 端到端工作流程

## 概述

本文档以 `demo-secret-app` 为例，完整演示：

1. 开发阶段使用 `dotenv` 从 `.env` 文件读取敏感信息
2. 生产阶段使用 systemd `EnvironmentFile=` 注入环境变量
3. 使用 shellflow 将应用部署到远程服务器（`trade`、`api`）
4. 全流程验证与优化建议

---

## 目录结构

```
shellflow/
├── bin/demo-secret-app/           # Rust 二进制 crate
│   ├── Cargo.toml
│   ├── src/main.rs
│   └── .env.example               # 开发环境示例
├── services/demo-secret-app/
│   ├── demo-secret-app.service     # systemd 单元模板
│   └── prod.env.example            # 生产环境变量示例
└── playbooks/
    └── deploy-demo.sh              # shellflow 部署剧本
```

---

## 1. 开发阶段 (控制机器)

### 1.1 应用代码

`bin/demo-secret-app/src/main.rs` 的核心逻辑：

```rust
// 开发模式：从 CARGO_MANIFEST_DIR/.env 加载
// 生产模式：从 systemd 注入的环境变量读取
fn maybe_load_dotenv() {
    // 未设置 RUN_ENV 或 SYSTEMD_SERVICE_NAME 时视为开发模式
    let is_dev = env::var("RUN_ENV").as_deref() == Ok("dev")
        || (env::var("SYSTEMD_SERVICE_NAME").is_err() && env::var("RUN_ENV").is_err());
    if is_dev {
        let search_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let dotenv_path = std::path::Path::new(&search_dir).join(".env");
        dotenvy::from_path(&dotenv_path).ok();
    }
}
```

### 1.2 本地开发

```bash
# 1. 创建 .env 文件
cp bin/demo-secret-app/.env.example bin/demo-secret-app/.env

# 2. 运行（自动加载 .env）
cargo run -p demo-secret-app

# 3. 模拟生产模式（直接传环境变量）
RUN_ENV=prod \
  API_KEY=test-key \
  API_SECRET=test-secret \
  DB_PASSWORD=test-pass \
  cargo run -p demo-secret-app
```

### 1.3 编译

```bash
# 本地编译（macOS ARM64）
cargo build --release -p demo-secret-app

# 交叉编译到 Linux x86_64（需要 cargo-zigbuild）
cargo zigbuild --release -p demo-secret-app --target x86_64-unknown-linux-gnu
```

---

## 2. 生产部署 (控制机器 -> 远程服务器)

### 2.1 前提条件

| 组件 | 要求 |
|------|------|
| 控制机器 | macOS/Linux, `bash`, `ssh`, `rsync` 或 `scp` |
| 远程服务器 | SSH 可达, `bash`, `systemd >= 254`, `sudo` (免密码) |
| ~/.ssh/config | 已配置 `trade` 和 `api` 主机别名 |
| shellflow | 已编译: `cargo build --release -p shellflow` |

### 2.2 部署流程

```
┌──────────────────────────────────────────────────────────────┐
│  控制机器 (macOS ARM64)                                      │
│                                                              │
│  1. cargo zigbuild --release --target x86_64-unknown-linux   │
│         ↓                                                    │
│  2. shellflow 解析 playbooks/deploy-demo.sh                  │
│         ↓                                                    │
│  3. @copy 二进制 + systemd 单元 → 远程 /tmp/                 │
│         ↓                                                    │
│  4. @remote sudo install → /usr/local/bin/                   │
│         ↓                                                    │
│  5. @remote sudo install 单元 → /etc/systemd/system/         │
│         ↓                                                    │
│  6. @remote printf + sudo install → /etc/demo-secret-app/env │
│         ↓                                                    │
│  7. @remote systemctl daemon-reload + enable + restart       │
│         ↓                                                    │
│  8. @remote journalctl 验证                                  │
└──────────────────────────────────────────────────────────────┘
```

### 2.3 执行部署

```bash
# 预览（不执行任何操作）
target/release/shellflow --dry-run --diff playbooks/deploy-demo.sh

# 正式部署
target/release/shellflow playbooks/deploy-demo.sh

# 仅部署到单个主机
target/release/shellflow -t trade playbooks/deploy-demo.sh

# 跳过构建步骤（如果二进制已是最新）
target/release/shellflow --skip build playbooks/deploy-demo.sh
```

### 2.4 验证输出

成功部署后，`journalctl` 输出应显示：

```
demo-secret-app[411254]: --- demo-secret-app ---
demo-secret-app[411254]: LOG_LEVEL=info
demo-secret-app[411254]:   API_KEY=sk-p...7890 (len=24)
demo-secret-app[411254]:   API_SECRET=ss-p...6789 (len=24)
demo-secret-app[411254]:   DB_PASSWORD=db-p...024! (len=20)
demo-secret-app[411254]: All secrets present. App is ready.
demo-secret-app[411254]: Deactivated successfully.
```

---

## 3. 安全设计

### 3.1 敏感信息保护

| 阶段 | 存储方式 | 权限 |
|------|----------|------|
| 开发 | `.env` 文件 | 600, 不提交到 Git |
| 传输 | SSH 加密通道 | N/A |
| 生产 | `/etc/demo-secret-app/env` | root:root, 0600 |
| 日志 | shellflow 自动掩码敏感值 | `***` 替换 |

### 3.2 shellflow 的 @env 掩码机制

shellflow 的 `@env KEY=value` 指令在输出中自动将值替换为 `***`，防止敏感信息泄露到日志中。

---

## 4. 优化建议与 DX 改进

### 4.1 当前痛点与解决方案

| 问题 | 当前方案 | 改进建议 |
|------|----------|----------|
| 交叉编译 | 手动 `cargo-zigbuild` | 集成到 CI/CD 流水线，或使用 `cross` Docker 镜像 |
| 密钥管理 | 明文写在 `@env` 中 | 使用 shellflow 的 `@secrets` 指令 + `age` 加密 |
| 服务类型 | `Type=oneshot` 只跑一次 | 改为 `Type=simple` 持守服务，或 `notify` 通知型 |
| 无健康检查 | 仅检查 journalctl | 添加 HTTP 健康端点 + `systemd-healthcheck` |
| 多环境 | 硬编码 env 值 | 使用 `@secrets` + 环境目录 (`env/prod/`, `env/staging/`) |

### 4.2 推荐工具链

| 工具 | 用途 | 说明 |
|------|------|------|
| [shellflow](https://github.com/longcipher/shellflow) | 部署编排 | 当前项目，DSL 驱动 |
| [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) | 交叉编译 | 利用 Zig 作为 C 链接器，零配置 |
| [age](https://age-encryption.org) | 加密密钥文件 | 被 shellflow 原生支持 (`@secrets`) |
| [systemd-creds](https://systemd.io/CREDENTIALS/) | 生产密钥存储 | systemd >= 254 原生加密凭据 |
| [just](https://github.com/casey/just) | 任务运行器 | 替代 Makefile，项目已有 `Justfile` |

### 4.3 简化流程的建议

#### 4.3.1 使用 shellflow `@secrets` 替代 `@env` 明文

```bash
# 当前（明文）：
# @env DEMO_API_KEY=sk-prod-abcdef1234567890

# 改进（加密）：
# 1. 创建加密文件
# shellflow secret encrypt -r age1... services/demo-secret-app/env/prod.env

# 2. 在 playbook 中引用
# @secrets services/demo-secret-app/env/prod.env.age
```

#### 4.3.2 使用 shellflow `deploy` 子命令

当前 shellflow 正在开发 `deploy` 子命令（参见 `docs/design-secrets.md`），未来可以：

```bash
# 单命令部署
shellflow deploy demo-secret-app

# 自动处理：
# - 从 services/<svc>/env/ 加载加密 env
# - 从 services/<svc>/units/ 加载 systemd 单元
# - 一致性校验（密钥冲突检测）
# - 自动 daemon-reload + restart
```

#### 4.3.3 添加 CI/CD 集成

在 `.github/workflows/deploy.yml` 中添加：

```yaml
- name: Cross-compile
  run: cargo zigbuild --release -p demo-secret-app --target x86_64-unknown-linux-gnu

- name: Deploy
  run: target/release/shellflow playbooks/deploy-demo.sh
```

#### 4.3.4 提取 `User`/`Group` 为可配置参数

当前 systemd 单元文件硬编码了 `User=nobody` 和 `Group=nobody`。在 Arch Linux 上 `nobody` 的 group 是 `nobody`（而非 `nogroup`）。建议：

- 在 playbook 中通过 `@env` 传递用户/组信息
- 使用 `sed` 或模板替换生成动态单元文件

---

## 5. 故障排查

### 5.1 常见问题

| 症状 | 原因 | 解决 |
|------|------|------|
| `Exec format error` | 二进制架构不匹配 | 使用 `cargo zigbuild` 交叉编译 |
| `Permission denied` on `/etc/...` | 文件权限不足 | 使用 `sudo` 执行安装操作 |
| `Unknown group 'nogroup'` | 组名不匹配 | 改为 `Group=nobody`（Arch Linux） |
| `DEMO_API_KEY: parameter null` | 环境变量未注入 | 检查 `@env` 声明和 shellflow 版本 |
| 远程 `rsync` 不可用 | 目标系统未安装 rsync | shellflow 自动降级为 `scp` |

### 5.2 调试技巧

```bash
# 详细输出
shellflow -vvv playbooks/deploy-demo.sh

# 仅执行特定步骤
shellflow --only install playbooks/deploy-demo.sh

# 跳过特定步骤
shellflow --skip build playbooks/deploy-demo.sh

# 远程手动验证
ssh trade "sudo journalctl -u demo-secret-app.service --no-pager -n 50"
ssh trade "sudo systemctl status demo-secret-app.service"
```

---

## 6. 参考

- [shellflow SKILL.md](../SKILL.md) — shellflow DSL 完整参考
- [design-secrets.md](design-secrets.md) — 密钥管理设计文档
- [design.md](design.md) — 项目设计文档
- [systemd EnvironmentFile=](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#EnvironmentFile=)
- [systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
- [dotenvy](https://crates.io/crates/dotenvy) — Rust dotenv 实现
