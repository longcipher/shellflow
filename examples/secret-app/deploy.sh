#!/usr/bin/env shellflow

# shellflow playbook: deploy the secret-app example to api and trade.
#
# Example of the **encrypted** workflow: systemd host-key-bound credentials
# are exported as environment variables by `shellflow cred-env exec` (the
# same shellflow binary, installed once per host) before exec'ing the app. No
# application code changes and no per-service starter script.
#
# Files (this directory):
#   src/, Cargo.toml       the app (reads API_KEY / API_SECRET / DB_PASSWORD)
#   secret-app.service     systemd unit (ExecStart via the shared cred-env
#                          helper — no per-service starter script)
#   deploy.sh              this playbook
#
# Workflow:
#   1. Build the app binary + the shellflow helper (static musl) locally.
#   2. Copy binaries + unit to a temp dir on each host.
#   3. Remote: install binaries + unit, seal the credential store
#      (cred-env credstore-install), enable + start, verify.
#
# Usage (from the repository root):
#   shellflow -k examples/secret-app/deploy.sh
#   shellflow --dry-run --diff examples/secret-app/deploy.sh
#   shellflow examples/secret-app/deploy.sh
#   shellflow -t trade examples/secret-app/deploy.sh
#
# ★ The `@env KEY=value` literals below are DEMO values (masked in output) so
# the example runs without an identity file. For real deployments use
# `@secrets` with an age-encrypted env file — see SKILL.md §4.

# @server api       api
# @server trade     trade
# @group  all       api,trade

# === Demo secrets (masked by shellflow in output) ===
# Literal values are for DSL demonstration only — see the warning above.
# @env API_KEY=demo-api-key-not-real-0001
# @env API_SECRET=demo-api-secret-not-real-002
# @env DB_PASSWORD=demo-db-password-not-real-03

# === 1. Local: build release binaries and create temp dir ===
# @name build
# @local
set -eu
STAMP="secret-app-$(date +%s)"
echo "==> STAMP=${STAMP}"
WORKDIR="/tmp/${STAMP}"
mkdir -p "${WORKDIR}"
REPO_ROOT="$(pwd)"
echo "==> Building secret-app (release, x86_64-linux)..."
cargo zigbuild --release -p secret-app --target x86_64-unknown-linux-gnu 2>&1
cp target/x86_64-unknown-linux-gnu/release/secret-app "${WORKDIR}/"
cp examples/secret-app/secret-app.service "${WORKDIR}/"
# The shared target-side helper IS this shellflow binary: `cred-env
# exec/render/credstore-install` run on the target once it is installed to
# /usr/local/bin/shellflow. Static musl build, no glibc coupling.
TARGET_ARCH="${TARGET_ARCH:-x86_64-unknown-linux-musl}"
echo "==> Building shellflow (target-side helper, ${TARGET_ARCH})..."
cargo zigbuild --release -p shellflow --target "${TARGET_ARCH}" 2>&1
cp "target/${TARGET_ARCH}/release/shellflow" "${WORKDIR}/shellflow"
echo "==> Build complete: $(ls -lh "${WORKDIR}/secret-app" | awk '{print $5}')"
# @export STAMP,WORKDIR

# === 2. Copy: ship binaries + unit to remote temp dir ===
# @name ship-artifacts
# @copy $WORKDIR/secret-app -> $WORKDIR/secret-app @all
# @copy $WORKDIR/secret-app.service -> $WORKDIR/secret-app.service @all
# @copy $WORKDIR/shellflow -> $WORKDIR/shellflow @all

# === 3. Remote: install binaries, unit, and systemd credentials ===
# @name install
# @remote all
# @timeout 120
set -eu
echo "==> Installing on $(hostname)..."

# Install binary under /opt/<svc>/bin/
sudo install -d -m 0755 /opt/secret-app/bin
sudo install -m 0755 "${WORKDIR}/secret-app" /opt/secret-app/bin/secret-app
echo "==> binary installed"

# Install the shared shellflow helper once per host (idempotent; version
# upgrades ship with each deploy). Its `cred-env` subcommands replace every
# per-service starter script: `cred-env exec` exports credentials as env vars
# and execs the app, `cred-env credstore-install` seals the credential store.
sudo install -m 0755 "${WORKDIR}/shellflow" /usr/local/bin/shellflow
echo "==> shellflow helper installed"

# Install systemd unit
sudo install -m 0644 "${WORKDIR}/secret-app.service" /etc/systemd/system/secret-app.service
echo "==> unit installed"

# Seal the per-service credential store with the helper (values travel on
# stdin, never argv; no shell involvement — bash/zsh login shell irrelevant).
# The unit loads them with
# LoadCredentialEncrypted=<KEY>:/etc/credstore.encrypted/secret-app/<KEY>.
# This example has no `@secrets` block, so the key list and value mapping that
# `@secrets` would normally provide are constructed here explicitly.
LT_SECRET_KEYS="API_KEY API_SECRET DB_PASSWORD" \
API_KEY="${API_KEY}" API_SECRET="${API_SECRET}" DB_PASSWORD="${DB_PASSWORD}" \
  /usr/local/bin/shellflow cred-env credstore-install secret-app

# Clean up temp files
rm -f "${WORKDIR}/secret-app" "${WORKDIR}/secret-app.service" "${WORKDIR}/shellflow"

# === 4. Remote: enable + run (oneshot) ===
# @name run
# @remote all
set -eu
sudo systemctl daemon-reload
sudo systemctl enable secret-app.service
sudo systemctl restart secret-app.service
sudo systemctl is-active secret-app.service

# === 5. Remote: verify ===
# @name verify
# @remote all
set -eu
echo "==> secret-app status: $(sudo systemctl is-active secret-app.service)"
echo "==> credential store audit:"
sudo ls -l /etc/credstore.encrypted/secret-app/
echo "==> last run output (values masked by app design):"
sudo journalctl -u secret-app.service --no-pager -n 8
echo "==> verify complete"
