package vault

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/config"
)

func TestAddBatchEmpty(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Capture vault.bin mtime to verify Save was not called.
	vaultPath := config.VaultFile(root)
	before, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("stat vault.bin: %v", err)
	}
	// Bump filesystem timestamp resolution.
	time.Sleep(10 * time.Millisecond)

	if err := v.AddBatch(nil); err != nil {
		t.Fatalf("AddBatch(nil): %v", err)
	}
	if err := v.AddBatch([]*Credential{}); err != nil {
		t.Fatalf("AddBatch([]): %v", err)
	}
	if len(v.List()) != 0 {
		t.Fatalf("vault should be empty after empty AddBatch, got %d", len(v.List()))
	}

	after, err := os.Stat(vaultPath)
	if err != nil {
		t.Fatalf("stat vault.bin after: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("vault.bin was rewritten on empty AddBatch (mtime changed)")
	}
}

func TestAddBatchSuccess(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	creds := []*Credential{
		{ID: NewID(), Name: "A", Real: "ra", Placeholder: "pa", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "B", Real: "rb", Placeholder: "pb", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "C", Real: "rc", Placeholder: "pc", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	if err := v.AddBatch(creds); err != nil {
		t.Fatalf("AddBatch: %v", err)
	}
	if got := len(v.List()); got != 3 {
		t.Fatalf("after AddBatch: len=%d, want 3", got)
	}
	for _, name := range []string{"A", "B", "C"} {
		if _, ok := v.Get(name); !ok {
			t.Errorf("Get(%q) returned false after AddBatch", name)
		}
	}

	// Re-open: confirm persistence (i.e. Save was called).
	v2, err := Open(root, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := len(v2.List()); got != 3 {
		t.Fatalf("reopened: len=%d, want 3", got)
	}
}

func TestAddBatchCallsSaveOnce(t *testing.T) {
	root := tempRoot(t)
	ks := newCountingKeystore(NewMemKeystore())
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	// Reset count after the constructor's own Save.
	ks.resetGets()

	creds := []*Credential{
		{ID: NewID(), Name: "A", Real: "ra", Placeholder: "pa", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "B", Real: "rb", Placeholder: "pb", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "C", Real: "rc", Placeholder: "pc", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	if err := v.AddBatch(creds); err != nil {
		t.Fatalf("AddBatch: %v", err)
	}
	// Save calls keystore.Get exactly once per Save.
	if got := ks.getsCount(); got != 1 {
		t.Errorf("AddBatch produced %d keystore.Get calls (want 1 = a single Save)", got)
	}
}

func TestAddBatchDuplicateWithinBatch(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	creds := []*Credential{
		{ID: NewID(), Name: "DUP", Real: "r1", Placeholder: "p1", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "OK", Real: "r2", Placeholder: "p2", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "DUP", Real: "r3", Placeholder: "p3", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	err = v.AddBatch(creds)
	if err == nil {
		t.Fatal("expected error on duplicate within batch")
	}
	if !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("want ErrDuplicateCredential, got: %v", err)
	}
	if got := len(v.List()); got != 0 {
		t.Fatalf("vault mutated on validation failure: len=%d, want 0", got)
	}
}

func TestAddBatchPlaceholderDuplicateWithinBatch(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	creds := []*Credential{
		{ID: NewID(), Name: "A", Real: "r1", Placeholder: "SAME_PH", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "B", Real: "r2", Placeholder: "SAME_PH", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	err = v.AddBatch(creds)
	if err == nil {
		t.Fatal("expected error on placeholder collision within batch")
	}
	if !errors.Is(err, ErrPlaceholderCollision) {
		t.Fatalf("want ErrPlaceholderCollision, got: %v", err)
	}
	if got := len(v.List()); got != 0 {
		t.Fatalf("vault mutated on validation failure: len=%d, want 0", got)
	}
}

func TestAddBatchDuplicateAgainstExisting(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if err := v.Add(&Credential{
		ID: NewID(), Name: "EXIST", Real: "r0", Placeholder: "p0", Source: "manual", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	preLen := len(v.List())

	creds := []*Credential{
		{ID: NewID(), Name: "NEW", Real: "r1", Placeholder: "p1", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "EXIST", Real: "r2", Placeholder: "p2", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	err = v.AddBatch(creds)
	if err == nil {
		t.Fatal("expected error on duplicate against existing")
	}
	if !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("want ErrDuplicateCredential, got: %v", err)
	}
	if got := len(v.List()); got != preLen {
		t.Fatalf("vault mutated on validation failure: len=%d, want %d", got, preLen)
	}
}

func TestAddBatchPlaceholderCollidesWithExisting(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if err := v.Add(&Credential{
		ID: NewID(), Name: "EXIST", Real: "r0", Placeholder: "SHARED", Source: "manual", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	preLen := len(v.List())

	creds := []*Credential{
		{ID: NewID(), Name: "NEW", Real: "r1", Placeholder: "SHARED", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	err = v.AddBatch(creds)
	if err == nil {
		t.Fatal("expected error on placeholder collision against existing")
	}
	if !errors.Is(err, ErrPlaceholderCollision) {
		t.Fatalf("want ErrPlaceholderCollision, got: %v", err)
	}
	if got := len(v.List()); got != preLen {
		t.Fatalf("vault mutated: len=%d, want %d", got, preLen)
	}
}

func TestAddBatchSaveFailure(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Force Save to fail by deleting the master key from the keystore.
	if err := ks.Delete("proj"); err != nil {
		t.Fatalf("Delete key: %v", err)
	}

	creds := []*Credential{
		{ID: NewID(), Name: "A", Real: "ra", Placeholder: "pa", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "B", Real: "rb", Placeholder: "pb", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	err = v.AddBatch(creds)
	if err == nil {
		t.Fatal("expected error when Save fails")
	}
	if !strings.Contains(err.Error(), "vault") {
		t.Logf("error: %v", err)
	}
	// In-memory slice must be rolled back to the pre-batch length.
	if got := len(v.List()); got != 0 {
		t.Fatalf("v.credentials not rolled back on Save failure: len=%d, want 0", got)
	}
}

func TestAddBatchDryRunRespectsDryRun(t *testing.T) {
	v := NewInMemoryVault(t.TempDir(), "proj")
	creds := []*Credential{
		{ID: NewID(), Name: "A", Real: "ra", Placeholder: "pa", Source: "manual", CreatedAt: time.Now().UTC()},
		{ID: NewID(), Name: "B", Real: "rb", Placeholder: "pb", Source: "manual", CreatedAt: time.Now().UTC()},
	}
	if err := v.AddBatch(creds); err != nil {
		t.Fatalf("AddBatch dry-run: %v", err)
	}
	if len(v.List()) != 2 {
		t.Fatalf("in-memory vault should contain creds after AddBatch")
	}
}

func TestHasCredential(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if v.HasCredential("anything") {
		t.Error("HasCredential should be false on empty vault")
	}

	if err := v.Add(&Credential{
		ID: NewID(), Name: "PRESENT", Real: "r", Placeholder: "ph", Source: "manual", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !v.HasCredential("PRESENT") {
		t.Error("HasCredential should be true for present name")
	}
	if v.HasCredential("ABSENT") {
		t.Error("HasCredential should be false for absent name")
	}
}

// countingKeystore wraps a Keystore and counts Get calls — used to assert
// that AddBatch issues a single Save() regardless of batch size. Each Save()
// invokes keystore.Get exactly once to retrieve the master key.
type countingKeystore struct {
	inner Keystore
	gets  int
}

func newCountingKeystore(inner Keystore) *countingKeystore {
	return &countingKeystore{inner: inner}
}

func (c *countingKeystore) Get(projectID string) ([32]byte, error) {
	c.gets++
	return c.inner.Get(projectID)
}

func (c *countingKeystore) Set(projectID string, key [32]byte) error {
	return c.inner.Set(projectID, key)
}

func (c *countingKeystore) Delete(projectID string) error {
	return c.inner.Delete(projectID)
}

func (c *countingKeystore) getsCount() int { return c.gets }
func (c *countingKeystore) resetGets()     { c.gets = 0 }
