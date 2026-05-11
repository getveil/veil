//go:build !testkeystore

package cli_test

import (
	"testing"

	"github.com/getveil/veil/internal/cli"
)

func TestProdBuildIgnoresMemKeystoreEnv(t *testing.T) {
	t.Setenv("VEIL_TEST_KEYSTORE", "mem")
	if _, ok := cli.MaybeTestKeystoreForTest(); ok {
		t.Fatal("prod build should not return a mem keystore even with env var set")
	}
}
