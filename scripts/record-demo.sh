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

# Use a stable demo-dir path so it can be pre-trusted in claude config
# (avoids the workspace-trust dialog). On macOS /tmp resolves to /private/tmp;
# we use /tmp here and the trust entry in ~/.claude.json points at the
# canonical /private/tmp/veil-demo path.
WORK="/tmp/veil-demo"
rm -rf "$WORK"
mkdir -p "$WORK"

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

# Pre-trust the demo dir in claude code's config so the workspace-trust
# dialog doesn't appear in the recording. macOS resolves /tmp to /private/tmp
# and claude stores trust under that canonical path.
CLAUDE_JSON="$HOME/.claude.json"
if [[ -f "$CLAUDE_JSON" ]] && command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import json, os
p = os.path.expanduser('~/.claude.json')
with open(p) as f:
    d = json.load(f)
key = '/private/tmp/veil-demo'
projects = d.setdefault('projects', {})
entry = projects.setdefault(key, {})
if not entry.get('hasTrustDialogAccepted'):
    entry['hasTrustDialogAccepted'] = True
    entry.setdefault('hasCompletedProjectOnboarding', True)
    entry.setdefault('projectOnboardingSeenCount', 1)
    entry.setdefault('hasClaudeMdExternalIncludesApproved', True)
    entry.setdefault('hasClaudeMdExternalIncludesWarningShown', True)
    entry.setdefault('allowedTools', [])
    entry.setdefault('mcpContextUris', [])
    entry.setdefault('mcpServers', {})
    entry.setdefault('enabledMcpjsonServers', [])
    entry.setdefault('disabledMcpjsonServers', [])
    with open(p, 'w') as f:
        json.dump(d, f, indent=2)
PY
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
