#!/usr/bin/env shellflow

# shellflow playbook: exercises every DSL feature against the `trade` and
# `api` servers from ~/.ssh/config.
#
#   - @server / @group declarations
#   - @local + @export cross-step state
#   - @copy with $VAR interpolation and --delete
#   - @remote with @only_if guards, @timeout, @env
#   - @name labeling for --only/--skip
#
# All remote commands are read-only (uname, env, date, df) or confined to
# /tmp so nothing on the servers is modified outside the sandbox dir.

# === Servers and groups (resolved via ~/.ssh/config Host aliases) ===
# @server trade     trade
# @server api      api
# @group  all      trade,api

# === Shared env for the whole playbook ===
# A literal @env value is treated as a secret and masked in output (design
# §9). Use the passthrough form to inherit from shellflow's environment; a
# demo secret below proves the masking.
# @env DEMO_SECRET=shellflow-topsecret
# @env HOME

# === 1. Local: build a version stamp and capture it ===
# @name stamp
# @local
set -eu
STAMP="sf-$(date +%s)"
echo "local stamp: ${STAMP}"
WORKDIR="/tmp/${STAMP}"
echo "workdir: ${WORKDIR}"
mkdir -p "${WORKDIR}"

# === Capture STAMP + WORKDIR into run state ===
# @export STAMP,WORKDIR

# === 2. Copy: ship a marker file to both hosts via rsync delta ===
# @name ship-marker
# @copy ./playbooks/marker.txt -> $WORKDIR/marker.txt @all

# === 3. Remote: read-only system facts on every host (parallel fan-out) ===
# @name facts
# @remote all
# @timeout 60
set -eu
echo "==> $(uname -a)"
echo "==> $(uname -m) / $(uname -s)"
echo "==> whoami=$(whoami) shell=${SHELL:-unknown}"
echo "==> pwd=$(pwd) home=${HOME:-unknown}"
echo "==> date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# === 4. Remote: /tmp-only state change + guard demonstration ===
# @name tmp-probe
# @remote all
# @only_if test -d /tmp
set -eu
echo "==> STAMP=${STAMP} WORKDIR=${WORKDIR}"
ls -ld "${WORKDIR}" 2>/dev/null || echo "marker dir not yet visible"
touch "${WORKDIR}/probe-$(hostname 2>/dev/null || echo h)-$(date +%s).txt"
echo "==> wrote probe into ${WORKDIR}"
df -h /tmp | tail -1

# === 5. Remote: verify the rsync marker is present (idempotent re-check) ===
# @name verify
# @remote all
# @only_if test -f "$WORKDIR/marker.txt"
set -eu
echo "==> marker present: ${WORKDIR}/marker.txt"
cat "${WORKDIR}/marker.txt"
echo "==> marker content checksum: $(cksum < "${WORKDIR}/marker.txt")"

# === 6. Remote: show the injected @env (proves env passthrough + masking) ===
# @name env-check
# @remote all
# @timeout 30
set -eu
echo "==> DEMO_SECRET=${DEMO_SECRET:?} (should be masked as ***)"
echo "==> HOME passthrough=${HOME:-unset}"
echo "==> count files in workdir: $(ls -1 "${WORKDIR}" | wc -l)"
