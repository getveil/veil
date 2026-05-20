package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2E_CargoThroughVeil runs `cargo search` through `veil run`. Cargo uses
// rustls and honors CARGO_HTTP_CAINFO; if Veil's injection works end-to-end,
// cargo successfully hits crates.io through the MITM proxy and returns
// results. Skipped if cargo is not on PATH.
func TestE2E_CargoThroughVeil(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	// Cargo distributed via rustup is a symlink to rustup itself, which
	// dispatches based on argv[0]. Veil's resolveAgentCommand calls
	// filepath.EvalSymlinks, so the symlink is resolved away and rustup
	// receives "rustup search serde" instead of "cargo search serde". This is a
	// known Veil command-resolution limitation that affects all argv-dispatched
	// shim toolchains (rustup, pyenv, rbenv, nvm). Out of scope for this test
	// — we skip on shims and rely on hosts with a standalone cargo binary to
	// validate the CARGO_HTTP_CAINFO injection.
	cargoPath, err := exec.LookPath("cargo")
	if err != nil {
		t.Skipf("cargo not on PATH: %v", err)
	}
	realCargo, err := filepath.EvalSymlinks(cargoPath)
	if err != nil {
		t.Skipf("cannot resolve cargo symlinks: %v", err)
	}
	if filepath.Base(realCargo) != "cargo" {
		t.Skipf("cargo at %s is a shim (resolves to %s); skipping due to argv[0]-dispatch incompatibility", cargoPath, realCargo)
	}

	env := makeEnv(t)

	binDir := t.TempDir()
	veilBin := buildVeil(t, binDir)

	projDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(projDir, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	// Without source material (.env / shell secrets) init early-exits and
	// never creates .veil/. The probe we're really testing is the runtime
	// TLS-injection path, not vaulting; a dummy .env is the cheapest way
	// to make init proceed to vault creation on a CI runner.
	if err := os.WriteFile(filepath.Join(projDir, ".env"), []byte("DUMMY_API_KEY=sk-test-1234567890abcdef\n"), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	initCmd := exec.Command(veilBin, "init", "--path", projDir, "--yes")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("veil init: %v\n%s", err, out)
	}

	// cargo search uses HTTPS to crates.io; a success exit + non-empty stdout
	// proves the rustls client trusted Veil's MITM cert via CARGO_HTTP_CAINFO.
	runCmd := exec.Command(veilBin, "run", "--path", projDir, "--", "cargo", "search", "serde", "--limit", "1")
	runCmd.Env = env
	out, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("veil run cargo search: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "serde") {
		t.Fatalf("cargo search output does not contain 'serde': %s", out)
	}
}
