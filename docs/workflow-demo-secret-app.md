# Demo Secret App — End-to-End Workflow

## Overview

This document walks through the complete lifecycle using `demo-secret-app`:

1. Development reads secrets from a local `.env` file via `dotenv`
2. In production, secrets are **age-encrypted at rest**; shellflow decrypts on
   the controller and the target only ever stores **systemd host-key-bound
   ciphertext**, with plaintext existing solely in tmpfs at runtime
3. Deploying the app to remote servers (`trade`, `api`) with shellflow
4. Full verification and auditing

## Directory Layout

```text
shellflow/
├── bin/demo-secret-app/              # Rust binary crate
│   ├── Cargo.toml
│   └── src/main.rs
├── services/demo-secret-app/         # service files (flat layout: only bin/ subdirectory)
│   ├── bin/
│   │   └── demo-secret-app-start     # starter: systemd credentials -> env -> exec
│   └── demo-secret-app.service       # systemd unit (ImportCredential= per key)
└── playbooks/
    └── deploy-demo.sh                # shellflow deploy playbook
```

The layout matches the private deployment-repo convention: programs live in
`bin/`, everything else is flat in the service directory. There is no
`configs/`, `env/`, or `units/` directory and no templates.

## 1. Development Stage (Controller)

### 1.1 Application Code

The core of `bin/demo-secret-app/src/main.rs`:

```rust
// Dev mode: load from CARGO_MANIFEST_DIR/.env
// Prod mode: read from environment variables injected by systemd
fn maybe_load_dotenv() {
    // Dev mode when RUN_ENV is unset or SYSTEMD_SERVICE_NAME is absent
    let is_dev = env::var("RUN_ENV").as_deref() == Ok("dev")
        || (env::var("SYSTEMD_SERVICE_NAME").is_err() && env::var("RUN_ENV").is_err());
    if is_dev {
        let search_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let dotenv_path = std::path::Path::new(&search_dir).join(".env");
        dotenvy::from_path(&dotenv_path).ok();
    }
}
```

### 1.2 Local Development

```bash
# 1. Create the .env file (gitignored — never commit it)
cp bin/demo-secret-app/.env.example bin/demo-secret-app/.env

# 2. Run (auto-loads .env)
cargo run -p demo-secret-app

# 3. Simulate production mode (pass env vars directly)
RUN_ENV=prod \
  API_KEY=test-key \
  API_SECRET=test-secret \
  DB_PASSWORD=test-pass \
  cargo run -p demo-secret-app
```

### 1.3 Build

```bash
# Local build (macOS ARM64)
cargo build --release -p demo-secret-app

# Cross-compile to Linux x86_64 (requires cargo-zigbuild)
cargo zigbuild --release -p demo-secret-app --target x86_64-unknown-linux-gnu
```

## 2. Production Deployment (Controller -> Remote Hosts)

### 2.1 Prerequisites

| Component | Requirement |
|-----------|-------------|
| Controller | macOS/Linux, `bash`, `ssh`, `rsync` or `scp`, `shellflow` |
| Remote host | SSH reachable, `bash`, `systemd >= 254`, passwordless `sudo` |
| ~/.ssh/config | `trade` and `api` host aliases configured |
| shellflow | `cargo build --release -p shellflow` |

### 2.2 Deploy Flow

```text
Controller (macOS)
  1. cargo zigbuild --release --target x86_64-unknown-linux-gnu
  2. shellflow parses playbooks/deploy-demo.sh (@env demo secrets, masked in output)
  3. @copy binary + unit + starter -> remote /tmp/<stamp>/
  4. @remote sudo install -> /opt/demo-secret-app/bin/ and /etc/systemd/system/
  5. @remote printf | sudo systemd-creds encrypt --with-key=host
        -> /etc/credstore.encrypted/<KEY>   (host-key-bound ciphertext, 0600 root)
  6. @remote systemctl daemon-reload + enable + restart
  7. @remote journalctl verification
```

The target disk holds **ciphertext only**; runtime plaintext exists solely in
the unit's tmpfs credential directory and is destroyed with the unit.

### 2.3 Running the Deployment

```bash
# Preview (executes nothing)
shellflow --dry-run --diff playbooks/deploy-demo.sh

# Real deployment
shellflow playbooks/deploy-demo.sh

# Deploy to a single host
shellflow -t trade playbooks/deploy-demo.sh

# Skip the build step (binary already up to date)
shellflow --skip build playbooks/deploy-demo.sh
```

### 2.4 Expected Output

After a successful deployment, `journalctl` shows:

```
demo-secret-app[411254]: --- demo-secret-app ---
demo-secret-app[411254]: LOG_LEVEL=info
demo-secret-app[411254]:   API_KEY=sk-p...7890 (len=24)
demo-secret-app[411254]:   API_SECRET=ss-p...6789 (len=24)
demo-secret-app[411254]:   DB_PASSWORD=db-p...024! (len=20)
demo-secret-app[411254]: All secrets present. App is ready.
demo-secret-app[411254]: Deactivated successfully.
```

## 3. Security Design

### 3.1 Secret Protection by Stage

| Stage | Storage | Permissions |
|-------|---------|-------------|
| Development | `.env` file | 600, never committed |
| Repo / transit | age ciphertext (`@secrets`) / SSH channel | ciphertext; shellflow masks output |
| Target disk | `/etc/credstore.encrypted/<KEY>` host-key-bound ciphertext | root:root, 0600 |
| Runtime | `$CREDENTIALS_DIRECTORY` tmpfs | unit lifetime, destroyed on exit |
| Logs | shellflow masks secret values | replaced with `***` |

### 3.2 Two Credential Injection Modes

- **Mode A — in-app loader (own code)**: read `$CREDENTIALS_DIRECTORY` early at
  startup and inject into the environment (~10 lines); `ExecStart` points
  directly at the binary.
- **Mode B — per-service starter (third-party/closed-source)**: the
  `bin/<svc>-start` wrapper exports credentials as environment variables and
  execs the real binary — zero application changes. This demo uses mode B.

### 3.3 shellflow's `@env` Masking

A literal `@env KEY=value` value is replaced with `***` in all shellflow
output. **Note: masking only covers shellflow's own output — it says nothing
about journald safety.** Audit the journal after deploying (see §4).

## 4. Auditing

```bash
ssh trade "sudo ls -l /etc/credstore.encrypted/"                    # one 0600 ciphertext per key
ssh trade "sudo find /opt /etc -name '*.env' | grep . && echo LEAK || echo clean"
ssh trade "sudo ls -l /run/credentials/demo-secret-app.service/"    # runtime plaintext only in tmpfs
ssh trade "sudo journalctl -u demo-secret-app.service | grep -iE 'password|secret' && echo LEAK || echo clean"
```

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Exec format error` | Binary architecture mismatch | Cross-compile with `cargo zigbuild` |
| `Permission denied` on `/etc/...` | Insufficient file permissions | Run installs with `sudo` |
| `Unknown group 'nogroup'` | Group name mismatch | Use `Group=nobody` (Arch Linux) |
| `DEMO_API_KEY: parameter null` | Environment variable not injected | Check `@env` declarations and shellflow version |
| Unit fails to start with no logs | Missing credential (`ImportCredential=` has no matching ciphertext) | Re-run the playbook's install step |
| Remote `rsync` unavailable | Target lacks rsync | shellflow falls back to `scp` automatically |

```bash
# Verbose output
shellflow -vvv playbooks/deploy-demo.sh

# Run one step only
shellflow --only install playbooks/deploy-demo.sh

# Skip a step
shellflow --skip build playbooks/deploy-demo.sh

# Manual remote verification
ssh trade "sudo journalctl -u demo-secret-app.service --no-pager -n 50"
ssh trade "sudo systemctl status demo-secret-app.service"
```

## 6. References

- [shellflow SKILL.md](../SKILL.md) — full shellflow DSL reference
- [design-secrets.md](design-secrets.md) — secrets design (including `@secrets {host}` per-host decryption)
- [design.md](design.md) — project design document
- [systemd.exec(5) LoadCredential=/ImportCredential=](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#LoadCredential=)
- [systemd-creds](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
- [dotenvy](https://crates.io/crates/dotenvy) — Rust dotenv implementation
