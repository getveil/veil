package cli

import (
	"testing"

	"github.com/getveil/veil/internal/vault"
)

// resetTestKeystoreForTest empties the singleton MemKeystore (used when the
// build was tagged with testkeystore and VEIL_TEST_KEYSTORE=mem is set). When
// the test keystore is not active, the test is skipped — these helpers exist
// only to support assertions about keystore contents in keystore-driven tests.
func resetTestKeystoreForTest(t *testing.T) {
	t.Helper()
	mem := requireMemTestKeystore(t)
	mem.Reset()
}

// snapshotTestKeystore returns the current set of keystore-account names in
// the singleton MemKeystore, skipping the test if the test keystore is not
// active.
func snapshotTestKeystore(t *testing.T) []string {
	t.Helper()
	return requireMemTestKeystore(t).Accounts()
}

func requireMemTestKeystore(t *testing.T) *vault.MemKeystore {
	t.Helper()
	ks, ok := MaybeTestKeystoreForTest()
	if !ok {
		t.Skip("test keystore not active; rebuild with -tags testkeystore and set VEIL_TEST_KEYSTORE=mem")
	}
	mem, ok := ks.(*vault.MemKeystore)
	if !ok {
		t.Skipf("test keystore is %T, expected *vault.MemKeystore", ks)
	}
	return mem
}
