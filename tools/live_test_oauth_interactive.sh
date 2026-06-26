#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

exec cargo run --offline --manifest-path "${ROOT_DIR}/Cargo.toml" --bin oauth_live_test -- "$@"
