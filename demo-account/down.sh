#!/usr/bin/env bash
# Destroy everything the demo created in the sandbox account. Safe to run when nothing is up.
#
#   bash demo-account/down.sh [sandbox-profile] [region]          # deletes everything in AWS
#   bash demo-account/down.sh --all [sandbox-profile] [region]    # also removes the local Terraform files
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
ALL=0; args=()
for a in "$@"; do
  if [[ "$a" == "--all" ]]; then ALL=1; else args+=("$a"); fi
done
if [[ -d "$HERE/.terraform" ]] && demo_is_up; then
  demo_profile "${args[0]:-}" "${args[1]:-}"
  "$TF" -chdir="$HERE" init -input=false >/dev/null
  destroy_sandbox
else
  log "Nothing to destroy - the sandbox demo is not up"
  PROFILE="${args[0]:-${SANDBOX_PROFILE:-sandbox}}"
fi
if [[ "$ALL" == 1 ]]; then
  rm -rf "$HERE/.terraform" "$HERE/.terraform.lock.hcl" "$HERE"/terraform.tfstate*
  log "Removed the local Terraform files"
fi
log "Down. The sandbox account is empty again (check: AWS_PROFILE=$PROFILE terraform -chdir=demo-account state list)"
