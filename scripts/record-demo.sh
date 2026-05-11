#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -x bin/veil ]]; then
  echo "Building veil binary..."
  make build
fi

if ! command -v asciinema >/dev/null 2>&1; then
  echo "asciinema not found. Install with: pip3 install asciinema  or  brew install asciinema" >&2
  exit 1
fi

WORK="$(mktemp -d -t veil-demo.XXXXXX)"
trap "rm -rf $WORK" EXIT

cp scripts/demo-fixture/.env.template "$WORK/.env"
mkdir -p demo

# Isolate the keychain: use file-backed keystore with a known passphrase
# so the demo doesn't touch the user's real keychain.
export VEIL_PASSPHRASE="demo-passphrase-not-secret"
export HOME="$WORK"
export VEIL_BIN="$REPO_ROOT/bin/veil"

cd "$WORK"
OUT="$REPO_ROOT/demo/veil-demo.cast"
asciinema rec --overwrite --command "bash $REPO_ROOT/scripts/demo.sh" "$OUT"

echo
echo "Cast saved to: $OUT"
echo
echo "To publish:"
echo "  asciinema auth   # one-time, browser flow"
echo "  asciinema upload $OUT"
echo "Then paste the returned cast ID into README.md (replace REPLACE_WITH_CAST_ID)."
