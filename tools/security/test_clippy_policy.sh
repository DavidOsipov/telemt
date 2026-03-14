#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_FILE="${REPO_ROOT}/.cargo/config.toml"
RUST_WORKFLOW="${REPO_ROOT}/.github/workflows/rust.yml"

require_contains() {
  local file="$1"
  local pattern="$2"
  if ! grep -Fq -- "$pattern" "$file"; then
    echo "Missing required pattern in ${file}: ${pattern}" >&2
    exit 1
  fi
}

require_not_contains() {
  local file="$1"
  local pattern="$2"
  if grep -Fq -- "$pattern" "$file"; then
    echo "Unexpected pattern in ${file}: ${pattern}" >&2
    exit 1
  fi
}

if [[ -f "$CONFIG_FILE" ]]; then
  require_contains "$CONFIG_FILE" '"-D", "clippy::expect_used"'
  require_not_contains "$CONFIG_FILE" '"-F", "clippy::expect_used"'
  require_not_contains "$CONFIG_FILE" '"-F", "clippy::unwrap_used"'
  require_not_contains "$CONFIG_FILE" '"-F", "clippy::todo"'
  require_not_contains "$CONFIG_FILE" '"-F", "clippy::unimplemented"'
  require_not_contains "$CONFIG_FILE" '"-D", "missing_docs"'
  require_not_contains "$CONFIG_FILE" '"-D", "unused_qualifications"'
  require_not_contains "$CONFIG_FILE" '"-D", "clippy::all"'
  require_not_contains "$CONFIG_FILE" '"-D", "clippy::pedantic"'
  require_not_contains "$CONFIG_FILE" '"-D", "clippy::cargo"'
fi

require_contains "$RUST_WORKFLOW" 'Run clippy for production targets (strict)'
require_contains "$RUST_WORKFLOW" 'Run clippy for test targets (scoped)'
require_contains "$RUST_WORKFLOW" 'Check benches compile'
require_contains "$RUST_WORKFLOW" 'cargo check --benches'
require_contains "$RUST_WORKFLOW" '-F clippy::expect_used'
require_contains "$RUST_WORKFLOW" '-F clippy::panic'
require_contains "$RUST_WORKFLOW" '-F clippy::unwrap_used'
require_contains "$RUST_WORKFLOW" '-F clippy::todo'
require_contains "$RUST_WORKFLOW" '-F clippy::unimplemented'
require_contains "$RUST_WORKFLOW" '-A clippy::expect_used'
require_contains "$RUST_WORKFLOW" '-A clippy::panic'
require_contains "$RUST_WORKFLOW" '-A clippy::unwrap_used'
require_contains "$RUST_WORKFLOW" '-A clippy::todo'
require_contains "$RUST_WORKFLOW" '-A clippy::unimplemented'
require_contains "$RUST_WORKFLOW" '-D clippy::correctness'
require_contains "$RUST_WORKFLOW" '-D clippy::all'
require_contains "$RUST_WORKFLOW" '-D clippy::pedantic'
require_contains "$RUST_WORKFLOW" '-D clippy::cargo'
require_contains "$RUST_WORKFLOW" '-D missing_docs'
require_contains "$RUST_WORKFLOW" '-D unused_qualifications'
require_contains "$RUST_WORKFLOW" '-A clippy::redundant_pub_crate'
require_contains "$RUST_WORKFLOW" '-A clippy::missing_const_for_fn'
require_contains "$RUST_WORKFLOW" '-A clippy::option_if_let_else'
require_contains "$RUST_WORKFLOW" '-A clippy::unused_async'
require_not_contains "$RUST_WORKFLOW" 'cargo clippy -- --cap-lints warn'

echo "Clippy policy regression tests passed."
