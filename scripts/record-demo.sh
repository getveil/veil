#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

if [[ ! -x bin/veil ]]; then
  echo "Building veil binary..."
  make build
fi

if ! command -v vhs >/dev/null 2>&1; then
  echo "vhs not found. Install with: brew install vhs" >&2
  exit 1
fi

WORK="$(mktemp -d -t veil-demo.XXXXXX)"

# Cleanup on exit: run veil uninstall to remove the demo's keychain entries,
# then delete the working directory.
cleanup() {
  if [[ -d "$WORK/.veil" ]]; then
    (cd "$WORK" && "$REPO_ROOT/bin/veil" uninstall --yes --force >/dev/null 2>&1 || true)
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

cp scripts/demo-fixture/.env.template "$WORK/.env"
cp scripts/demo-fixture/CLAUDE.md "$WORK/CLAUDE.md"

# Substitute a real GitHub token (from `gh auth`) into the demo .env so the
# curl call returns real user data instead of 401. Falls back to the synthetic
# value baked into .env.template if gh isn't available.
if command -v gh >/dev/null 2>&1; then
  REAL_GH_TOKEN=$(gh auth token 2>/dev/null || true)
  if [[ -n "$REAL_GH_TOKEN" ]]; then
    sed -i.bak "s|^GITHUB_TOKEN=.*|GITHUB_TOKEN=${REAL_GH_TOKEN}|" "$WORK/.env"
    rm -f "$WORK/.env.bak"
  fi
fi

# Sanitize env to a minimal whitelist so the recorder's shell env (which may
# contain secret-like vars unrelated to the demo) does NOT leak into the cast
# as warnings from veil's parent-env scanner.
env -i \
  HOME="$HOME" \
  PATH="$PATH" \
  USER="${USER:-$LOGNAME}" \
  TERM=xterm-256color \
  TMPDIR="${TMPDIR:-/tmp}" \
  LANG=en_US.UTF-8 \
  VEIL_BIN="$REPO_ROOT/bin/veil" \
  VEIL_DEMO_DIR="$WORK" \
  vhs scripts/demo.tape

echo
echo "Demo rendered to: $REPO_ROOT/.github/demo.gif"
