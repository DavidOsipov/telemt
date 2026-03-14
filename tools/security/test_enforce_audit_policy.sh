#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES_DIR="${SCRIPT_DIR}/fixtures"
POLICY_SCRIPT="${SCRIPT_DIR}/enforce_audit_policy.sh"

run_expect_success() {
  local audit_json="$1"
  local risk_file="$2"
  shift 2
  if ! bash "${POLICY_SCRIPT}" --audit-json "$audit_json" --risk-file "$risk_file" "$@" >/dev/null; then
    echo "Expected success but failed: audit=${audit_json}, risk=${risk_file}" >&2
    exit 1
  fi
}

run_expect_failure() {
  local audit_json="$1"
  local risk_file="$2"
  shift 2
  if bash "${POLICY_SCRIPT}" --audit-json "$audit_json" --risk-file "$risk_file" "$@" >/dev/null 2>&1; then
    echo "Expected failure but passed: audit=${audit_json}, risk=${risk_file}" >&2
    exit 1
  fi
}

run_expect_success \
  "${FIXTURES_DIR}/audit_report_clean.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml"

run_expect_failure \
  "${FIXTURES_DIR}/audit_report_vulnerable.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml" \
  --severity high

run_expect_success \
  "${FIXTURES_DIR}/audit_report_vulnerable.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml" \
  --severity critical

run_expect_success \
  "${FIXTURES_DIR}/audit_report_vulnerable.json" \
  "${FIXTURES_DIR}/risk_acceptance_valid.toml" \
  --severity high

run_expect_failure \
  "${FIXTURES_DIR}/audit_report_vulnerable.json" \
  "${FIXTURES_DIR}/risk_acceptance_missing_reason.toml" \
  --severity high

run_expect_failure \
  "${FIXTURES_DIR}/audit_report_medium.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml"

run_expect_failure \
  "${FIXTURES_DIR}/audit_report_medium.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml" \
  --severity medium

run_expect_success \
  "${FIXTURES_DIR}/audit_report_medium.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml" \
  --severity high

run_expect_success \
  "${FIXTURES_DIR}/audit_report_low.json" \
  "${FIXTURES_DIR}/risk_acceptance_empty.toml"

echo "Security policy regression tests passed."