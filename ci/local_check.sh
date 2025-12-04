#!/usr/bin/env bash
set -euo pipefail

echo "==> cargo fmt"
cargo fmt --all

echo "==> cargo clippy"
cargo clippy --workspace --all-targets -- -D warnings

echo "==> cargo test"
cargo test --workspace --all-targets
