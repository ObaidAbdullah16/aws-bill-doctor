#!/usr/bin/env bash
# One command: build the deliberately misconfigured sandbox, scan it, destroy it.
# The destroy runs even if the scan fails (trap). Cost: about $0.05 per run.
#
#   bash demo-account/run-demo.sh [sandbox-profile] [region]   # default: SANDBOX_PROFILE from _setup/config.env
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
demo_profile "${1:-}" "${2:-}"
ensure_scanner
confirm_sandbox

trap destroy_sandbox EXIT
"$TF" -chdir="$HERE" init -input=false >/dev/null
"$TF" -chdir="$HERE" apply -auto-approve -input=false "${TFVARS[@]}"

log "Waiting 90 seconds so every AWS API reports the new resources..."
sleep 90
scan_sandbox
echo
log "Report: $OUT/report.html  (the trap now destroys the sandbox resources)"
