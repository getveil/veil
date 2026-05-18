package runner

import (
	"bytes"
	"strings"
	"testing"
)

func TestScanUnvaultedSecretLikes_FindsUnvaulted(t *testing.T) {
	environ := []string{
		"HOME=/home/user",
		"OPENAI_API_KEY=sk-proj-notvaulted1234567890abc",
		"ANTHROPIC_API_KEY=sk-ant-alsonotvaultedxyz1234567",
	}
	vaultNames := []string{"GITHUB_TOKEN"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 2 {
		t.Fatalf("got %d names, want 2: %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_IgnoresVaultedNames(t *testing.T) {
	environ := []string{
		"OPENAI_API_KEY=sk-proj-realvalue1234567890abc",
	}
	vaultNames := []string{"OPENAI_API_KEY"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (already in vault): %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_IgnoresAllowlisted(t *testing.T) {
	environ := []string{
		"MY_PRIVATE_JWT=eyJhbGciOiJIUzI1NiJ9.really-looks-like-a-secret.0123456789abcdef",
	}
	vaultNames := []string{}
	allow := map[string]struct{}{"MY_PRIVATE_JWT": {}}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (allowlisted): %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_CaseInsensitiveVaultMatch(t *testing.T) {
	environ := []string{
		"openai_api_key=sk-proj-notvaulted1234567890abc",
	}
	vaultNames := []string{"OPENAI_API_KEY"}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (vault match is case-insensitive): %v", len(got), got)
	}
}

func TestScanUnvaultedSecretLikes_CaseInsensitiveAllowMatch(t *testing.T) {
	environ := []string{
		"OPENAI_API_KEY=sk-proj-notvaulted1234567890abc",
	}
	vaultNames := []string{}
	// User passed --allow-env-secret with different case from the actual env var.
	allow := map[string]struct{}{"openai_api_key": {}}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (allow match must be case-insensitive): %v", len(got), got)
	}
}

// TestScanUnvaultedSecretLikes_IgnoresPOSIXNames verifies the runtime scan
// shares the scanner's denylist: POSIX / shell / system names that happen to
// have high-entropy values (PATH with many dirs, long session IDs, etc.)
// must not trip the check, because a user running `veil run env` in a normal
// terminal should not see warnings about PATH "looking like a secret."
func TestScanUnvaultedSecretLikes_IgnoresPOSIXNames(t *testing.T) {
	environ := []string{
		"PATH=/usr/local/opt/rust/bin:/Users/x/.cargo/bin:/Users/x/.rbenv/shims:/usr/bin:/bin",
		"PWD=/Users/x/work/some/deep/path",
		"OLDPWD=/Users/x/work/previous/path",
		"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.abc123def456/Listeners",
		"TMPDIR=/var/folders/ab/cdefg1234567hijklmnop/T/",
		"_=/usr/local/bin/veil",
		"SHLVL=2",
	}
	vaultNames := []string{}
	allow := map[string]struct{}{}

	got := scanUnvaultedSecretLikes(environ, vaultNames, allow)

	if len(got) != 0 {
		t.Fatalf("got %d names, want 0 (POSIX-standard names must be denylisted): %v", len(got), got)
	}
}

// TestScanUnvaultedSecretLikes_NameGateFiltersTrivialValues asserts the
// IsSecretLike value-shape gate prevents the runtime "unvaulted" warning
// from firing on trivial-value name matches like LOG_LEVEL_AUTH=info,
// which used to force users to add --allow-env-secret for every match.
func TestScanUnvaultedSecretLikes_NameGateFiltersTrivialValues(t *testing.T) {
	environ := []string{
		"LOG_LEVEL_AUTH=info",
		"AUTH_METHOD=oauth",
		"DB_PASSWORD_PROMPT=true",
		"KEY_LAYOUT=us",
		// And a real-shaped secret that must still be reported.
		"GHCR_TOKEN=ghp_realtoken1234567",
	}
	got := scanUnvaultedSecretLikes(environ, nil, nil)
	if len(got) != 1 || got[0] != "GHCR_TOKEN" {
		t.Fatalf("got %v, want [GHCR_TOKEN]", got)
	}
}

func TestPrintUnvaultedWarning_FormatsLoud(t *testing.T) {
	var buf bytes.Buffer
	printUnvaultedWarning(&buf, []string{"FOO_TOKEN", "BAR_SECRET"})
	out := buf.String()

	for _, want := range []string{"FOO_TOKEN", "BAR_SECRET", "--allow-env-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q:\n%s", want, out)
		}
	}
}
