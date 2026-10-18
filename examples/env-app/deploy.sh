#!/usr/bin/env shellflow

# shellflow playbook: deploy the env-app example to api.
#
# Example of the **plain env** workflow: no age encryption, no systemd
# credentials, no target-side helper. Configuration ships as plaintext env
# values (`@env` in this playbook → written to a 0600 EnvironmentFile on the
# target). Simple, but the values are readable by root on the target disk —
# that trade-off is the point of the example. See examples/secret-app for the
# encrypted equivalent of the same shape.
#
# Files (this directory):
#   src/, Cargo.toml     the app (reads APP_GREETING / APP_TOKEN)
#   env-app.service      systemd unit (EnvironmentFile= plaintext)
#   deploy.sh            this playbook
#
# Usage (from the repository root):
#   shellflow -k examples/env-app/deploy.sh
#   shellflow --dry-run --diff examples/env-app/deploy.sh
#   shellflow examples/env-app/deploy.sh

# @server api       api

# === Plain configuration (plaintext by design — do NOT put real secrets here;
#     use the secret-app workflow for anything sensitive) ===
# @env APP_GREETING=hello-from-shellflow
# @env APP_TOKEN=demo-token-not-real-0001

# === 1. Local: build release binary and create temp dir ===
# @name build
# @local
set -eu
STAMP="env-app-$(date +%s)"
echo "==> STAMP=${STAMP}"
WORKDIR="/tmp/${STAMP}"
mkdir -p "${WORKDIR}"
echo "==> Building env-app (release, x86_64-linux)..."
cargo zigbuild --release -p env-app --target x86_64-unknown-linux-gnu 2>&1
cp target/x86_64-unknown-linux-gnu/release/env-app "${WORKDIR}/"
cp examples/env-app/env-app.service "${WORKDIR}/"
echo "==> Build complete: $(ls -lh "${WORKDIR}/env-app" | awk '{print $5}')"
# @export STAMP,WORKDIR

# === 2. Copy: ship binary + unit to remote temp dir ===
# @name ship-artifacts
# @copy $WORKDIR/env-app -> $WORKDIR/env-app @api
# @copy $WORKDIR/env-app.service -> $WORKDIR/env-app.service @api

# === 3. Remote: install binary + unit + plaintext env file ===
# @name install
# @remote api
# @timeout 120
set -eu
echo "==> Installing on $(hostname)..."

sudo install -d -m 0755 /opt/env-app/bin
sudo install -m 0755 "${WORKDIR}/env-app" /opt/env-app/bin/env-app
sudo install -d -m 0755 /etc/env-app
sudo install -m 0644 "${WORKDIR}/env-app.service" /etc/systemd/system/env-app.service

# The plaintext env file: values come from the `@env` literals above
# (injected into this block's environment by shellflow, masked in output).
# Written 0600 root:root — readable by root only. `set -eu` fails the block
# on unset variables; the empty check catches set-but-empty values.
: > /tmp/env-app.env
for key in APP_GREETING APP_TOKEN; do
  val=$(printenv "$key")
  [ -n "$val" ] || { echo "!! ${key} is empty, aborting" >&2; exit 1; }
  printf '%s=%s\n' "$key" "$val" >> /tmp/env-app.env
done
sudo install -m 0600 /tmp/env-app.env /etc/env-app/env-app.env
rm -f /tmp/env-app.env
echo "==> installed (plaintext env on target disk — the demo's trade-off)"

rm -f "${WORKDIR}/env-app" "${WORKDIR}/env-app.service"

# === 4. Remote: enable + run (oneshot) ===
# @name run
# @remote api
set -eu
sudo systemctl daemon-reload
sudo systemctl enable env-app.service
sudo systemctl restart env-app.service
sudo systemctl is-active env-app.service

# === 5. Remote: verify ===
# @name verify
# @remote api
set -eu
echo "==> env-app status: $(sudo systemctl is-active env-app.service)"
echo "==> last run output (values masked by the app itself):"
sudo journalctl -u env-app.service --no-pager -n 8
echo "==> verify complete"
