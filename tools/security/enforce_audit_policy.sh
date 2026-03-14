#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RISK_FILE="${REPO_ROOT}/.security/advisory-risk-acceptance.toml"
AUDIT_JSON_FILE=""

usage() {
  cat <<'EOF'
Usage: tools/security/enforce_audit_policy.sh [--audit-json <path>] [--risk-file <path>]

Enforces Phase 0 advisory policy:
- evaluates cargo-audit vulnerabilities at the configured severity threshold
- blocks unknown advisories
- allows only explicitly documented, non-expired temporary exceptions
EOF
}

while (($# > 0)); do
  case "$1" in
    --audit-json)
      AUDIT_JSON_FILE="$2"
      shift 2
      ;;
    --risk-file)
      RISK_FILE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$RISK_FILE" ]]; then
  echo "Risk acceptance file not found: $RISK_FILE" >&2
  exit 2
fi

if [[ -n "$AUDIT_JSON_FILE" ]]; then
  if [[ ! -f "$AUDIT_JSON_FILE" ]]; then
    echo "Audit JSON file not found: $AUDIT_JSON_FILE" >&2
    exit 2
  fi
  AUDIT_JSON_CONTENT="$(cat "$AUDIT_JSON_FILE")"
else
  pushd "$REPO_ROOT" >/dev/null
  AUDIT_JSON_CONTENT="$(cargo audit --json)"
  popd >/dev/null
fi

export AUDIT_JSON_CONTENT
export RISK_FILE

python3 - <<'PY'
import json
import os
import sys
from datetime import date

try:
    import tomllib
except ModuleNotFoundError as exc:
    print(f"Python 3.11+ is required (missing tomllib): {exc}", file=sys.stderr)
    sys.exit(2)


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_exceptions(path: str):
    with open(path, "rb") as f:
        raw = tomllib.load(f)

    exceptions = raw.get("exceptions", [])
    if not isinstance(exceptions, list):
        fail("Invalid risk acceptance file: 'exceptions' must be an array")

    by_id = {}
    today = date.today()

    for idx, item in enumerate(exceptions, start=1):
        if not isinstance(item, dict):
            fail(f"Invalid exception entry #{idx}: must be a table")

        advisory_id = str(item.get("id", "")).strip()
        owner = str(item.get("owner", "")).strip()
        reason = str(item.get("reason", "")).strip()
        tracking = str(item.get("tracking_issue", "")).strip()
        expires = str(item.get("expires", "")).strip()

        if not advisory_id:
            fail(f"Invalid exception entry #{idx}: 'id' is required")
        if not owner:
            fail(f"Invalid exception '{advisory_id}': 'owner' is required")
        if not reason:
            fail(f"Invalid exception '{advisory_id}': 'reason' is required")
        if not tracking:
            fail(f"Invalid exception '{advisory_id}': 'tracking_issue' is required")
        if not expires:
            fail(f"Invalid exception '{advisory_id}': 'expires' is required")

        try:
            expires_on = date.fromisoformat(expires)
        except ValueError:
            fail(
                f"Invalid exception '{advisory_id}': 'expires' must be YYYY-MM-DD"
            )

        if expires_on < today:
            fail(
                f"Risk acceptance for {advisory_id} expired on {expires_on.isoformat()}"
            )

        by_id[advisory_id] = {
            "owner": owner,
            "reason": reason,
            "tracking_issue": tracking,
            "expires": expires_on.isoformat(),
        }

    return by_id


def main() -> int:
    report = json.loads(os.environ["AUDIT_JSON_CONTENT"])
    exceptions = parse_exceptions(os.environ["RISK_FILE"])

    vulnerabilities = report.get("vulnerabilities", {}).get("list", [])
    if not vulnerabilities:
        print("Policy check passed: no high/critical vulnerabilities found.")
        return 0

    blocked = []
    accepted = []

    for vuln in vulnerabilities:
        advisory = vuln.get("advisory", {})
        advisory_id = str(advisory.get("id", "UNKNOWN"))

        if advisory_id in exceptions:
            accepted.append((advisory_id, exceptions[advisory_id]))
            continue

        pkg = vuln.get("package", {})
        blocked.append(
            {
                "id": advisory_id,
                "title": advisory.get("title", "(no title)"),
                "package": pkg.get("name", "(unknown)"),
                "version": pkg.get("version", "(unknown)"),
            }
        )

    for advisory_id, data in accepted:
        print(
            "Accepted temporary risk: "
            f"{advisory_id} owner={data['owner']} expires={data['expires']} "
            f"tracking={data['tracking_issue']}"
        )

    if blocked:
        print("Policy check failed: unresolved high/critical advisories:", file=sys.stderr)
        for item in blocked:
            print(
                f"- {item['id']} {item['package']}@{item['version']}: {item['title']}",
                file=sys.stderr,
            )
        print(
            "Add a temporary entry to .security/advisory-risk-acceptance.toml "
            "only when formal risk acceptance is approved.",
            file=sys.stderr,
        )
        return 1

    print("Policy check passed: all detected advisories have valid temporary acceptance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY