#!/usr/bin/env bash
# Offline end-to-end demo against the bundled fixtures. No network is used:
# registry answers come from examples/registry.json.
set -u
SW="uv run --frozen squatwatch"
cd "$(dirname "$0")/.."

step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }
run() { step "$*"; "$@"; echo "[exit code $?]"; }

run $SW snapshot
run $SW check -e pypi reqeusts jeIlyfish python3-dateutil requests
run $SW check -e npm crossenv @typess/node lodash
run $SW scan examples/webapp-py examples/webapp-js --config examples/squatwatch.toml
run $SW review examples/archives/clean-sdist-1.0.0.tar.gz examples/archives/hooked-sdist-0.1.0.tar.gz \
  examples/archives/intree-backend-0.1.0.tar.gz examples/archives/inert-npm-fixture-0.1.0.tgz \
  examples/archives/startup_pth-0.1.0-py3-none-any.whl examples/archives/unsafe-paths-0.1.0.tar.gz
step "$SW scan examples/webapp-py --config examples/squatwatch.toml --format sarif | head -20"
$SW scan examples/webapp-py --config examples/squatwatch.toml --format sarif | head -20
exit 0
