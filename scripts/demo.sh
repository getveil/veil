#!/bin/bash
set -euo pipefail

# Find the script directory and source the helper.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HERE}/demo-magic.sh"

VEIL_BIN="${VEIL_BIN:-veil}"
TYPE_SPEED=30

clear_screen

p "# Your project has secrets the AI agent shouldn't see:"
wait 0.8
pe "cat .env"
wait 1.5

p "# Veil migrates them into the OS keychain and leaves format-aware placeholders:"
wait 0.8
pe "${VEIL_BIN} init --yes"
wait 1.5
pe "cat .env"
wait 2

p "# Now run an agent through the proxy — placeholders get swapped at the network layer:"
wait 0.8
pe "${VEIL_BIN} run -- bash -c 'set -a; source .env; curl -s -H \"Authorization: token \$GITHUB_TOKEN\" https://httpbin.org/headers | jq .headers.Authorization'"
wait 2

p "# Every credential injection is logged locally:"
wait 0.8
pe "${VEIL_BIN} log --since 1m"
wait 2
