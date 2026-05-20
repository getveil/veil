package vault

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getveil/veil/internal/config"
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

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

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
	err = v.Add(dup)
	if err == nil {
		t.Fatal("expected error on duplicate name")
	}
	if !errors.Is(err, ErrDuplicateCredential) {
		t.Fatalf("expected ErrDuplicateCredential, got: %v", err)
	}
}

func TestPlaceholderCollision(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

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
	err = v.Add(c2)
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

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &Credential{
		ID:          NewID(),
		Name:        "KEY",
		Real:        "val",
		Placeholder: "ph",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	_ = v.Add(cred)

	deleted, err := v.Delete("KEY")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !deleted {
		t.Fatal("Delete returned false")
	}
	if _, ok := v.Get("KEY"); ok {
		t.Fatal("credential still found after Delete")
	}
	deleted, err = v.Delete("KEY")
	if err != nil {
		t.Fatalf("Delete (second): %v", err)
	}
	if deleted {
		t.Fatal("second Delete should return false")
	}
}

func TestListAndPlaceholderMap(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

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

func TestNames(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	if got := v.Names(); len(got) != 0 {
		t.Fatalf("Names() on empty vault = %v, want empty", got)
	}

	for i, name := range []string{"OPENAI_API_KEY", "DATABASE_URL", "STRIPE_SECRET_KEY"} {
		if err := v.Add(&Credential{
			ID:          NewID(),
			Name:        name,
			Real:        "r-" + name,
			Placeholder: "p-" + name,
			Source:      "manual",
			CreatedAt:   time.Now().UTC().Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("Add %q: %v", name, err)
		}
	}

	got := v.Names()
	want := map[string]bool{
		"OPENAI_API_KEY":    true,
		"DATABASE_URL":      true,
		"STRIPE_SECRET_KEY": true,
	}
	if len(got) != len(want) {
		t.Fatalf("Names() len = %d, want %d (%v)", len(got), len(want), got)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("Names() contains unexpected %q", n)
		}
	}
}

func TestSaveAtomicityAndBackup(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

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

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	_, ok := v.Get("NONEXISTENT")
	if ok {
		t.Fatal("Get should return false for missing credential")
	}
}

func TestDeleteSaveError(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &Credential{
		ID:          NewID(),
		Name:        "KEY",
		Real:        "val",
		Placeholder: "ph",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Make .veil/ directory read-only so Save cannot write.
	stateDir := config.ProjectStateDir(root)
	if err := os.Chmod(stateDir, 0500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	defer func() { _ = os.Chmod(stateDir, 0700) }()

	deleted, err := v.Delete("KEY")
	if err == nil {
		t.Fatal("expected error when Save fails")
	}
	if !deleted {
		t.Fatal("Delete should return true even when Save fails")
	}
}

func TestAddPlaceholderCollisionMessage(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()
	v, err := CreateVault(dir, "test-collision", ks)
	if err != nil {
		t.Fatal(err)
	}

	cred1 := &Credential{
		ID:          NewID(),
		Name:        "KEY_A",
		Real:        "real-a",
		Placeholder: "ph-shared",
		Source:      "test",
	}
	if err := v.Add(cred1); err != nil {
		t.Fatal(err)
	}

	cred2 := &Credential{
		ID:          NewID(),
		Name:        "KEY_B",
		Real:        "real-b",
		Placeholder: "ph-shared",
		Source:      "test",
	}
	err = v.Add(cred2)
	if err == nil {
		t.Fatal("expected placeholder collision error")
	}
	if !strings.Contains(err.Error(), "veil remove") {
		t.Errorf("collision error should suggest veil remove, got: %v", err)
	}
}

func TestOpenCorruptedVaultMessage(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()

	// Create a valid vault first (to register the key in the keystore).
	v, err := CreateVault(dir, "test-corrupt", ks)
	if err != nil {
		t.Fatal(err)
	}
	_ = v

	// Corrupt the vault file.
	vaultPath := filepath.Join(dir, ".veil", "vault.bin")
	if err := os.WriteFile(vaultPath, []byte("corrupted-data"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a backup file so the recovery message can reference it.
	backupPath := filepath.Join(dir, ".veil", "vault.bin.bak")
	if err := os.WriteFile(backupPath, []byte("backup-data"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err = Open(dir, ks)
	if err == nil {
		t.Fatal("expected error for corrupted vault")
	}
	// The error should be about corruption, not a generic Go error.
	if !strings.Contains(err.Error(), "corrupt") && !strings.Contains(err.Error(), "unseal") {
		t.Errorf("error should reference corruption, got: %v", err)
	}
}

func TestAddPersistsOnReopen(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()

	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	cred := &Credential{
		ID:          NewID(),
		Name:        "DB_PASSWORD",
		Real:        "super-secret-123",
		Placeholder: "ph-db-password",
		Source:      "manual",
		CreatedAt:   time.Now().UTC(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Re-open vault from disk.
	v2, err := Open(root, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	got, ok := v2.Get("DB_PASSWORD")
	if !ok {
		t.Fatal("credential not found after re-open")
	}
	if got.Real != "super-secret-123" {
		t.Fatalf("Real = %q, want %q", got.Real, "super-secret-123")
	}
	if got.Placeholder != "ph-db-password" {
		t.Fatalf("Placeholder = %q, want %q", got.Placeholder, "ph-db-password")
	}
	if got.Source != "manual" {
		t.Fatalf("Source = %q, want %q", got.Source, "manual")
	}
	if got.ID != cred.ID {
		t.Fatalf("ID = %q, want %q", got.ID, cred.ID)
	}
}

// TestDecodeCredentials_FiltersStaleSchemeRecords pins the contract behind
// the raw-JSON pre-filter chosen for the on-disk compat path (Phase 9,
// item 5): pre-v1 records carrying `"scheme":"aws"` / `"github_app"` /
// `"basic"` are dropped BEFORE unmarshaling, so the Scheme-less Credential
// struct never loads them as Bearer placeholders the proxy would inject.
func TestDecodeCredentials_FiltersStaleSchemeRecords(t *testing.T) {
	plaintext := []byte(`[
		{"id":"a","name":"bearer-1","real":"r1","placeholder":"ph1","source":"env","created_at":"2024-01-01T00:00:00Z"},
		{"id":"b","name":"aws-prod","scheme":"aws","real":"r2","placeholder":"ph2","source":"env","created_at":"2024-01-01T00:00:00Z","aws_access_key_id":"AKIAEXAMPLE"},
		{"id":"c","name":"gh-app","scheme":"github_app","real":"r3","placeholder":"ph3","source":"env","created_at":"2024-01-01T00:00:00Z"},
		{"id":"d","name":"basic-1","scheme":"basic","real":"r4","placeholder":"ph4","source":"env","created_at":"2024-01-01T00:00:00Z","username":"alice"}
	]`)
	got, err := decodeCredentials(plaintext)
	if err != nil {
		t.Fatalf("decodeCredentials: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 survivor after filtering aws/github_app/basic, got %d (%v)", len(got), got)
	}
	if got[0].Name != "bearer-1" {
		t.Errorf("survivor = %q, want bearer-1", got[0].Name)
	}
}

// TestOpen_TolerantOfStaleAWSGitHubAppAndBasicRecords verifies the
// risk-register promise from the launch cuts: a vault written by v0.1.x
// with aws / github_app / basic scheme records (including their now-removed
// extra fields like aws_access_key_id, username) must still open cleanly,
// with the stale entries silently filtered out.
func TestOpen_TolerantOfStaleAWSGitHubAppAndBasicRecords(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	if _, err := CreateVault(root, "proj", ks); err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	// Marshal a credential set that mixes supported schemes with stale aws /
	// github_app / basic records carrying extra fields the current struct no
	// longer has. json.Unmarshal must silently drop the unknown fields, and
	// Open must filter out the stale-scheme records.
	rawRecords := []map[string]any{
		{
			"id": NewID(), "name": "OPENAI_API_KEY", "real": "sk-real",
			"placeholder": "sk-ph", "source": "env", "created_at": time.Now().UTC(),
		},
		{
			"id": NewID(), "name": "AWS", "scheme": "aws",
			"aws_access_key_id":             "AKIAIOSFODNN7EXAMPLE",
			"aws_access_key_id_placeholder": "AKIAEXAMPLE_PH",
			"aws_session_token":             "tok",
			"aws_session_token_placeholder": "tok-ph",
			"real":                          "secret", "placeholder": "ph-aws",
			"source": "env", "created_at": time.Now().UTC(),
		},
		{
			"id": NewID(), "name": "GH_APP", "scheme": "github_app",
			"github_app_id": "123", "github_installation_id": "456",
			"github_app_private_key_pem": "-----BEGIN-----",
			"real":                       "pem", "placeholder": "ph-gh",
			"source": "env", "created_at": time.Now().UTC(),
		},
		{
			"id": NewID(), "name": "ARTIFACTORY", "scheme": "basic",
			"username":             "alice",
			"username_placeholder": "VEIL_USER_PH",
			"username_var":         "ARTIFACTORY_USER",
			"real":                 "secret", "placeholder": "ph-basic",
			"source": "env", "created_at": time.Now().UTC(),
		},
	}
	data, err := json.Marshal(rawRecords)
	if err != nil {
		t.Fatalf("marshal raw records: %v", err)
	}

	// Seal with the project's key and overwrite vault.bin.
	key, err := ks.Get("proj")
	if err != nil {
		t.Fatalf("keystore Get: %v", err)
	}
	blob, err := Seal(key, data)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := os.WriteFile(config.VaultFile(root), blob, 0o600); err != nil {
		t.Fatalf("write vault.bin: %v", err)
	}

	v, err := Open(root, ks)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := v.List()
	if len(got) != 1 {
		t.Fatalf("expected 1 surviving credential, got %d: %+v", len(got), got)
	}
	if got[0].Name != "OPENAI_API_KEY" {
		t.Errorf("surviving credential = %q, want OPENAI_API_KEY", got[0].Name)
	}
}

func TestCredentialJSONBackwardCompat(t *testing.T) {
	// Old on-disk format predates fields that have since been removed.
	// Unmarshal must succeed with json silently dropping unknown fields.
	oldJSON := `{"id":"x","name":"n","real":"r","placeholder":"p","source":"manual","created_at":"2024-01-01T00:00:00Z","username":"u","username_placeholder":"up"}`
	var got Credential
	if err := json.Unmarshal([]byte(oldJSON), &got); err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if got.Name != "n" || got.Real != "r" || got.Placeholder != "p" {
		t.Errorf("required fields missing after round-trip: %+v", got)
	}
}
