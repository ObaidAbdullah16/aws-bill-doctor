#!/usr/bin/env bash
# Is the deliberately misconfigured sandbox demo running?
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
if [[ ! -d "$HERE/.terraform" ]] || ! demo_is_up; then
  echo "bill-doctor sandbox demo: DOWN (costs nothing)"
  exit 0
fi
echo "bill-doctor sandbox demo: UP (~\$0.03/hour) - destroy it: bash demo-account/down.sh"
"$TF" -chdir="$HERE" state list | grep -v '^data\.' | sed 's/^/  /'
