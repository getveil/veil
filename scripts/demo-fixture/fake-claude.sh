#!/bin/bash
# Simulates a Claude Code session that hits the GitHub API.
# The persona output is scripted; the curl is real — veil intercepts it,
# substitutes the placeholder with the real token from the keychain, and
# forwards to api.github.com. If the keychain token is synthetic (demo),
# GitHub returns 401 and we fall back to a hard-coded username; the audit
# log still records the injection event, which is the actual demo point.

set -a
. ./.env 2>/dev/null
set +a

PURPLE='\033[1;35m'
DIM='\033[2m'
GREEN='\033[1;32m'
WHITE='\033[1m'
RESET='\033[0m'

printf '%b●%b %bClaude%b\n' "$PURPLE" "$RESET" "$WHITE" "$RESET"
printf '   I will fetch your GitHub username using the token in your env.\n'
sleep 0.7
printf '\n'

printf '   %b$ curl -sH "Authorization: token $GITHUB_TOKEN" https://api.github.com/user%b\n' "$DIM" "$RESET"
sleep 0.4

# The real call. Veil's proxy intercepts and substitutes the placeholder.
response=$(curl -sH "Authorization: token $GITHUB_TOKEN" https://api.github.com/user 2>/dev/null)
username=$(printf '%s' "$response" | jq -r '.login // empty' 2>/dev/null)
[[ -z "$username" ]] && username="8enji"

sleep 0.6
printf '\n'
printf '   Your GitHub username is %b%s%b.\n' "$GREEN" "$username" "$RESET"
sleep 0.6
printf '\n'
printf '   %b(My view of GITHUB_TOKEN was %.16s… — the real value never reached me.)%b\n' "$DIM" "$GITHUB_TOKEN" "$RESET"
