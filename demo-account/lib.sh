#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables defined here are used by the scripts that source it
# Shared helpers for the deliberately misconfigured sandbox demo (up, scan, down, run-demo).
# Sourced, not executed. The sandbox is a SEPARATE, EMPTY AWS account (Guide 08 creates it);
# its AWS CLI profile comes from the first argument or SANDBOX_PROFILE in _setup/config.env.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
if [[ -f "$REPO_ROOT/../_setup/config.env" ]]; then
  # shellcheck disable=SC1091
  source "$REPO_ROOT/../_setup/config.env"
fi
OUT="$REPO_ROOT/sample-security-report-real"
MAIN_PROFILE="${AWS_PROFILE:-}"      # your everyday profile (e.g. obaid), before we switch to the sandbox

log()  { printf '\033[1;34m[demo]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; exit 1; }

TF="${TF:-$(command -v terraform || command -v tofu || true)}"   # Terraform or OpenTofu
[[ -n "$TF" ]] || die "terraform (or tofu) is not installed (bash _setup/install-tools-wsl.sh)"
command -v aws >/dev/null || die "aws is not installed (bash _setup/install-tools-wsl.sh)"

# demo_profile [profile] [region]: sets PROFILE, REGION, ACCOUNT, TFVARS
demo_profile() {
  PROFILE="${1:-${SANDBOX_PROFILE:-sandbox}}"
  REGION="${2:-${AWS_REGION:-ap-southeast-2}}"
  ACCOUNT="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text 2>/dev/null)" \
    || die "Profile '$PROFILE' is not logged in. Run: bash _setup/aws-login.sh --profile $PROFILE   (Guide 08 creates the sandbox project)"
  export AWS_PROFILE="$PROFILE"
  TFVARS=(-var "sandbox_account_id=$ACCOUNT" -var "region=$REGION")
}

# The account behind the profile must be typed again before anything insecure is created.
confirm_sandbox() {
  local main=""
  if [[ -n "$MAIN_PROFILE" && "$MAIN_PROFILE" != "$PROFILE" ]]; then
    main="$(aws sts get-caller-identity --profile "$MAIN_PROFILE" --query Account --output text 2>/dev/null || true)"
    [[ "$main" == "$ACCOUNT" ]] && die "Profile '$PROFILE' points at your MAIN account ($ACCOUNT), not the sandbox. Log it in to the SANDBOX project: bash _setup/aws-login.sh --profile $PROFILE (choose the sandbox project)"
  fi
  echo "This will create DELIBERATELY INSECURE resources in account $ACCOUNT (profile $PROFILE, region $REGION)."
  if [[ "${CONFIRM_ACCOUNT:-}" != "$ACCOUNT" ]]; then
    read -r -p "Type the account ID to confirm it is the EMPTY sandbox account: " answer
    [[ "$answer" == "$ACCOUNT" ]] || die "Account IDs do not match - nothing was created."
  fi
}

demo_is_up() { [[ -n "$("$TF" -chdir="$HERE" state list 2>/dev/null | grep -v '^data\.' || true)" ]]; }

# billdoctor (this repo, installed into .venv the first time) and prowler (pipx, by the installer)
ensure_scanner() {
  if ! command -v billdoctor >/dev/null 2>&1; then
    if [[ ! -x "$REPO_ROOT/.venv/bin/billdoctor" ]]; then
      log "Installing billdoctor into $REPO_ROOT/.venv (first time only)"
      python3 -m venv "$REPO_ROOT/.venv" || die "python3-venv is missing: sudo apt-get install -y python3-venv"
      "$REPO_ROOT/.venv/bin/pip" install -q -e "$REPO_ROOT"
    fi
    export PATH="$REPO_ROOT/.venv/bin:$PATH"
  fi
  command -v prowler >/dev/null 2>&1 || die "prowler is not installed: bash _setup/install-tools-wsl.sh (or pipx install prowler==5.47.0)"
}

scan_sandbox() {
  ensure_scanner
  log "Scanning the sandbox with the security baseline check (5-10 minutes)"
  billdoctor security scan --profile "$PROFILE" --regions "$REGION" \
    --label "Demo sandbox (deliberately misconfigured)" \
    --banner "DEMO ACCOUNT - a real AWS sandbox deliberately misconfigured with Terraform (demo-account/ in this repo), fake secrets only, destroyed right after the scan." \
    --out "$OUT"
  log "Report: $OUT/report.html"
}

destroy_sandbox() {
  log "Destroying the demo resources..."
  if ! "$TF" -chdir="$HERE" destroy -auto-approve -input=false "${TFVARS[@]}"; then
    warn "DESTROY FAILED. Run this until it succeeds:  bash demo-account/down.sh $PROFILE $REGION"
    return 1
  fi
}
