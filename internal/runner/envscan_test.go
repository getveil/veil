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
