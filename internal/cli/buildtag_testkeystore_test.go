//go:build testkeystore

package cli_test

import (
	"testing"

	"github.com/8enji/veil/internal/cli"
)

func TestTestBuildHonorsMemKeystoreEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	ks, ok := cli.MaybeTestKeystoreForTest()
	if !ok {
		t.Fatal("testkeystore build should return mem keystore when env var is set")
	}
	if ks == nil {
		t.Fatal("testkeystore build returned ok=true but nil keystore")
	}
}

func TestTestBuildIgnoresMissingEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "")
	if _, ok := cli.MaybeTestKeystoreForTest(); ok {
		t.Fatal("testkeystore build should not return mem keystore when env var is unset")
	}
}
