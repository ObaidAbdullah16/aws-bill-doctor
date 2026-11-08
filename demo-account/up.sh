#!/usr/bin/env bash
# Build the deliberately misconfigured sandbox and leave it running, so you can look at it in
# the console or scan it several times. Costs ~$0.03/hour while up - always finish with down.sh.
# (run-demo.sh does up + scan + down in one go.)
#
#   bash demo-account/up.sh [sandbox-profile] [region]      # default: SANDBOX_PROFILE from _setup/config.env
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
demo_profile "${1:-}" "${2:-}"
confirm_sandbox
"$TF" -chdir="$HERE" init -input=false >/dev/null
"$TF" -chdir="$HERE" apply -auto-approve -input=false "${TFVARS[@]}"
log "The insecure demo account is up. Scan it:  bash demo-account/scan.sh   Destroy it:  bash demo-account/down.sh"
