package vault

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/config"
)

func tempRoot(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

func TestCreateAndOpen(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "test-project", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if len(v.List()) != 0 {
		t.Fatal("expected empty vault")
	}
	if v.ProjectID() != "test-project" {
		t.Fatalf("projectID = %q, want %q", v.ProjectID(), "test-project")
	}

	// Re-open the vault from disk.
	v2, err := Open(root, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(v2.List()) != 0 {
		t.Fatal("re-opened vault should be empty")
	}
	if v2.ProjectID() != "test-project" {
		t.Fatalf("re-opened projectID = %q", v2.ProjectID())
	}
}

func TestCreateVaultWritesGitignore(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	_, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(config.VaultGitignoreFile(root))
	if err != nil {
		t.Fatalf("read gitignore: %v", err)
	}
	if string(data) != "*\n" {
		t.Fatalf("gitignore content = %q, want %q", data, "*\n")
	}
}

func TestAddAndGet(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatal(err)
	}

	cred := &Credential{
		ID:          NewID(),
		Name:        "OPENAI_API_KEY",
		Real:        "sk-real-secret",
		Placeholder: "sk-placeholder-abc",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	got, ok := v.Get("OPENAI_API_KEY")
	if !ok {
		t.Fatal("Get returned false")
	}
	if got.Real != "sk-real-secret" {
		t.Fatalf("Real = %q", got.Real)
	}
}

func TestAddDuplicateName(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	cred := &Credential{
		ID:          NewID(),
		Name:        "KEY",
		Real:        "v1",
		Placeholder: "p1",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatal(err)
	}

	dup := &Credential{
		ID:          NewID(),
		Name:        "KEY",
		Real:        "v2",
		Placeholder: "p2",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	err := v.Add(dup)
	if err == nil {
		t.Fatal("expected error on duplicate name")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlaceholderCollision(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	c1 := &Credential{
		ID:          NewID(),
		Name:        "KEY_A",
		Real:        "real-a",
		Placeholder: "SAME_PLACEHOLDER",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(c1); err != nil {
		t.Fatal(err)
	}

	c2 := &Credential{
		ID:          NewID(),
		Name:        "KEY_B",
		Real:        "real-b",
		Placeholder: "SAME_PLACEHOLDER",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	err := v.Add(c2)
	if err == nil {
		t.Fatal("expected error on placeholder collision")
	}
	if !strings.Contains(err.Error(), "placeholder collision") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDelete(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	cred := &Credential{
		ID:          NewID(),
		Name:        "KEY",
		Real:        "val",
		Placeholder: "ph",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	_ = v.Add(cred)

	if !v.Delete("KEY") {
		t.Fatal("Delete returned false")
	}
	if _, ok := v.Get("KEY"); ok {
		t.Fatal("credential still found after Delete")
	}
	if v.Delete("KEY") {
		t.Fatal("second Delete should return false")
	}
}

func TestListAndPlaceholderMap(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	for i, name := range []string{"A", "B", "C"} {
		_ = v.Add(&Credential{
			ID:          NewID(),
			Name:        name,
			Real:        "real-" + name,
			Placeholder: "ph-" + name,
			Source:      "manual",
			CreatedAt:   time.Now().UTC().Add(time.Duration(i) * time.Second),
		})
	}

	list := v.List()
	if len(list) != 3 {
		t.Fatalf("List len = %d, want 3", len(list))
	}

	// Verify List returns a copy.
	list[0] = nil
	if v.List()[0] == nil {
		t.Fatal("List should return a copy")
	}

	pm := v.PlaceholderMap()
	if len(pm) != 3 {
		t.Fatalf("PlaceholderMap len = %d, want 3", len(pm))
	}
	if pm["ph-B"].Name != "B" {
		t.Fatal("PlaceholderMap lookup failed for ph-B")
	}

	// Credentials is an alias for List.
	creds := v.Credentials()
	if len(creds) != 3 {
		t.Fatalf("Credentials len = %d", len(creds))
	}
}

func TestSaveAtomicityAndBackup(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	// After CreateVault, vault.bin exists but vault.bin.bak does not.
	vaultPath := config.VaultFile(root)
	backupPath := config.VaultBackupFile(root)

	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("vault.bin missing after CreateVault: %v", err)
	}

	// Add a credential — this triggers Save which should create a backup.
	_ = v.Add(&Credential{
		ID:          NewID(),
		Name:        "K",
		Real:        "r",
		Placeholder: "p",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	})

	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("vault.bin.bak missing after Add: %v", err)
	}
}

func TestOpenCorruptedVault(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	_, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatal(err)
	}

	// Overwrite vault.bin with garbage.
	vaultPath := config.VaultFile(root)
	if err := os.WriteFile(vaultPath, []byte("this is garbage data"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(root, ks)
	if err == nil {
		t.Fatal("expected error on corrupted vault")
	}
}

func TestGetMissing(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, _ := CreateVault(root, "proj", ks)

	_, ok := v.Get("NONEXISTENT")
	if ok {
		t.Fatal("Get should return false for missing credential")
	}
}
