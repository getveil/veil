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

# Cleanup on exit: run veil uninstall to remove the demo's keychain entries,
# then delete the working directory. Both run regardless of recording outcome.
cleanup() {
  if [[ -d "$WORK/.veil" ]]; then
    (cd "$WORK" && "$REPO_ROOT/bin/veil" uninstall --yes --force >/dev/null 2>&1 || true)
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cp scripts/demo-fixture/.env.template "$WORK/.env"
mkdir -p demo

# We do NOT override HOME — macOS keychain access requires the real user's
# login keychain, which is resolved through the user session, not $HOME.
# On the first run, macOS may show a one-time "Always Allow" prompt for
# the veil binary to access the keychain item; click Always Allow.
export VEIL_BIN="$REPO_ROOT/bin/veil"

cd "$WORK"
OUT="$REPO_ROOT/demo/veil-demo.cast"

# Sanitize env to a minimal whitelist so the recorder's shell env (which may
# contain secret-like vars unrelated to the demo) does NOT leak into the cast
# as warnings from veil's parent-env scanner.
asciinema rec --overwrite --command \
  "env -i HOME='$HOME' PATH='$PATH' USER='${USER:-$LOGNAME}' TERM=xterm-256color TMPDIR='${TMPDIR:-/tmp}' LANG=en_US.UTF-8 VEIL_BIN='$VEIL_BIN' bash $REPO_ROOT/scripts/demo.sh" \
  "$OUT"

echo
echo "Cast saved to: $OUT"
echo
echo "To publish:"
echo "  asciinema upload $OUT"
echo "Then paste the returned cast ID into README.md (replace REPLACE_WITH_CAST_ID)."
