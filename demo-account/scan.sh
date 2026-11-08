#!/usr/bin/env bash
# Scan the running sandbox (after up.sh) and write sample-security-report-real/.
#   bash demo-account/scan.sh [sandbox-profile] [region]
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
demo_profile "${1:-}" "${2:-}"
demo_is_up || die "The sandbox demo is not up. Start it with: bash demo-account/up.sh   (or use run-demo.sh)"
scan_sandbox
