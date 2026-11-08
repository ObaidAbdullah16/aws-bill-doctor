#!/usr/bin/env bash
# Scan YOUR OWN AWS account (read-only): cost/waste (S1) + security baseline (S8) in one report.
# Same as the monthly "Scan my AWS account" workflow, but from your laptop. Free (read-only API calls;
# Cost Explorer is not used unless you add --cost-explorer to billdoctor yourself).
#
#   bash scripts/scan-my-account.sh                      # regions: your AWS_REGION + us-east-1 (project account: AWS_REGION only)
#   REGIONS=all bash scripts/scan-my-account.sh          # every enabled region (slower)
# Output: audits/my-account/<date>/index.html   (audits/ is git-ignored: never commit it)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -f "$REPO_ROOT/../_setup/config.env" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/../_setup/config.env"
fi
PROFILE="${PROFILE:-${AWS_PROFILE:-obaid}}"
if [[ "${AWS_ACCOUNT_TYPE:-classic}" == project ]]; then
  # A project account (new AWS sign-up) only has resources in its own Region; other Regions answer "access denied".
  REGIONS="${REGIONS:-${AWS_REGION:-ap-southeast-2}}"
else
  REGIONS="${REGIONS:-${AWS_REGION:-ap-southeast-2},us-east-1}"
fi
OUT="$REPO_ROOT/audits/my-account/$(date +%Y-%m-%d)"

aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1 || { echo "Log in first: bash _setup/aws-login.sh"; exit 1; }
if ! command -v billdoctor >/dev/null 2>&1; then
  if [[ ! -x "$REPO_ROOT/.venv/bin/billdoctor" ]]; then
    echo "Installing billdoctor into $REPO_ROOT/.venv (first time only)"
    python3 -m venv "$REPO_ROOT/.venv"
    "$REPO_ROOT/.venv/bin/pip" install -q -e "$REPO_ROOT"
  fi
  export PATH="$REPO_ROOT/.venv/bin:$PATH"
fi
command -v prowler >/dev/null 2>&1 || { echo "prowler is not installed: bash _setup/install-tools-wsl.sh"; exit 1; }

billdoctor health-check --profile "$PROFILE" --regions "$REGIONS" --label "My account" --out "$OUT"
echo
echo "Open: $OUT/index.html   (in WSL: explorer.exe \"\$(wslpath -w $OUT/index.html)\")"
echo "This is YOUR account's data: keep it private, never commit or publish it."
