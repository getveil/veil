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

func TestCredentialBasicFields(t *testing.T) {
	c := &Credential{
		ID:                  "abc",
		Name:                "github-pat",
		Real:                "ghp_realvalue",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
	}

	c.Zero()

	if c.Username != "" {
		t.Errorf("Zero() did not clear Username: %q", c.Username)
	}
	if c.UsernamePlaceholder != "" {
		t.Errorf("Zero() did not clear UsernamePlaceholder: %q", c.UsernamePlaceholder)
	}
	if c.Real != "" || c.Placeholder != "" {
		t.Error("Zero() should still clear Real and Placeholder")
	}
}

func TestCredentialJSONRoundTripBasic(t *testing.T) {
	original := &Credential{
		ID:                  "id1",
		Name:                "github-pat",
		Real:                "ghp_realvalue",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
		CreatedAt:           time.Unix(1712000000, 0).UTC(),
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Credential
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Username != "johndoe" || got.UsernamePlaceholder != "VEIL_PH_USER" {
		t.Errorf("round-trip lost basic fields: %+v", got)
	}
}

func TestAddRejectsUsernamePlaceholderCollision(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}

	first := &Credential{
		ID: "a", Name: "first",
		Real: "r1", Placeholder: "VEIL_PH_SECRET_AAAA",
		Username: "alice", UsernamePlaceholder: "VEIL_PH_USER_SHARED",
	}
	if err := v.Add(first); err != nil {
		t.Fatalf("Add first: %v", err)
	}

	// Second credential whose Placeholder collides with first's UsernamePlaceholder.
	second := &Credential{
		ID: "b", Name: "second",
		Real: "r2", Placeholder: "VEIL_PH_USER_SHARED",
	}
	if err := v.Add(second); err == nil {
		t.Fatal("Add should have rejected placeholder colliding with existing UsernamePlaceholder")
	}

	// Third credential whose UsernamePlaceholder collides with first's Placeholder.
	third := &Credential{
		ID: "c", Name: "third",
		Real: "r3", Placeholder: "VEIL_PH_SECRET_BBBB",
		Username: "carol", UsernamePlaceholder: "VEIL_PH_SECRET_AAAA",
	}
	if err := v.Add(third); err == nil {
		t.Fatal("Add should have rejected UsernamePlaceholder colliding with existing Placeholder")
	}
}

func TestPlaceholderMapIncludesUsernamePlaceholder(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	cred := &Credential{
		ID: "a", Name: "github-pat",
		Real:                "ghp_real",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "johndoe",
		UsernamePlaceholder: "VEIL_PH_USER",
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}

	m := v.PlaceholderMap()
	if got := m["VEIL_PH_SECRET"]; got == nil || got.Name != "github-pat" {
		t.Errorf("PlaceholderMap missing secret placeholder entry")
	}
	if got := m["VEIL_PH_USER"]; got == nil || got.Name != "github-pat" {
		t.Errorf("PlaceholderMap missing username placeholder entry")
	}
}

func TestPlaceholderSetIncludesUsernamePlaceholder(t *testing.T) {
	root := tempRoot(t)
	ks := NewMemKeystore()
	v, err := CreateVault(root, "proj", ks)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	cred := &Credential{
		ID: "a", Name: "gh",
		Real:                "r",
		Placeholder:         "VEIL_PH_SECRET",
		Username:            "u",
		UsernamePlaceholder: "VEIL_PH_USER",
	}
	if err := v.Add(cred); err != nil {
		t.Fatalf("Add: %v", err)
	}
	s := v.PlaceholderSet()
	if _, ok := s["VEIL_PH_SECRET"]; !ok {
		t.Error("set missing secret placeholder")
	}
	if _, ok := s["VEIL_PH_USER"]; !ok {
		t.Error("set missing username placeholder")
	}
}

func TestPlaceholderMap_IncludesAWSFields(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()
	v, err := CreateVault(dir, "pid", ks)
	if err != nil {
		t.Fatal(err)
	}
	cred := &Credential{
		ID:                         NewID(),
		Name:                       "aws-prod",
		Real:                       "real-secret",
		Placeholder:                "VeilAWSSecret",
		Scheme:                     "aws",
		AWSAccessKeyID:             "AKIAREAL",
		AWSAccessKeyIDPlaceholder:  "AKIAPH",
		AWSSessionToken:            "realtok",
		AWSSessionTokenPlaceholder: "VeilSess",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
	}
	if err := v.Add(cred); err != nil {
		t.Fatal(err)
	}
	pm := v.PlaceholderMap()
	for _, ph := range []string{"VeilAWSSecret", "AKIAPH", "VeilSess"} {
		if pm[ph] == nil {
			t.Errorf("PlaceholderMap missing %q", ph)
		}
	}

	set := v.PlaceholderSet()
	for _, ph := range []string{"VeilAWSSecret", "AKIAPH", "VeilSess"} {
		if _, ok := set[ph]; !ok {
			t.Errorf("PlaceholderSet missing %q", ph)
		}
	}
}

func TestCredential_AWSFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()
	v, err := CreateVault(dir, "pid", ks)
	if err != nil {
		t.Fatal(err)
	}

	orig := &Credential{
		ID:                         NewID(),
		Name:                       "aws-prod",
		Real:                       "real-secret-key",
		Placeholder:                "VeilAWSSecretVEIL",
		Scheme:                     "aws",
		AWSAccessKeyID:             "AKIAIOSFODNN7EXAMPLE",
		AWSAccessKeyIDPlaceholder:  "AKIAVEIL3X9Z2Y1W8VQR",
		AWSSessionToken:            "FwoGZXIv...realtoken",
		AWSSessionTokenPlaceholder: "VeilAWSSessTok",
		AllowedHosts:               []string{"*.amazonaws.com"},
		CreatedAt:                  time.Now(),
	}
	if err := v.Add(orig); err != nil {
		t.Fatal(err)
	}

	v2, err := Open(dir, ks)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := v2.Get("aws-prod")
	if !ok {
		t.Fatal("credential not found after reload")
	}
	if got.Scheme != "aws" || got.AWSAccessKeyID != orig.AWSAccessKeyID ||
		got.AWSAccessKeyIDPlaceholder != orig.AWSAccessKeyIDPlaceholder ||
		got.AWSSessionToken != orig.AWSSessionToken ||
		got.AWSSessionTokenPlaceholder != orig.AWSSessionTokenPlaceholder {
		t.Fatalf("aws fields not preserved: %+v", got)
	}
}

func TestCredential_GitHubAppFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	ks := NewMemKeystore()
	v, err := CreateVault(dir, "pid", ks)
	if err != nil {
		t.Fatal(err)
	}

	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
	placeholder := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n"
	orig := &Credential{
		ID:                   NewID(),
		Name:                 "gh-app",
		Real:                 pem,
		Placeholder:          placeholder,
		Scheme:               "github_app",
		GitHubAppID:          123456,
		GitHubInstallationID: 789012,
		AllowedHosts:         []string{"api.github.com"},
		CreatedAt:            time.Now(),
	}
	if err := v.Add(orig); err != nil {
		t.Fatal(err)
	}
	v2, err := Open(dir, ks)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := v2.Get("gh-app")
	if got.Real != pem || got.Placeholder != placeholder ||
		got.GitHubAppID != 123456 || got.GitHubInstallationID != 789012 {
		t.Fatalf("github app fields not preserved: %+v", got)
	}
}

func TestCredential_Zero_ClearsAWSFields(t *testing.T) {
	c := &Credential{
		Scheme:                     "aws",
		Real:                       "secret",
		Placeholder:                "ph",
		AWSAccessKeyID:             "AKIA",
		AWSAccessKeyIDPlaceholder:  "AKIAPH",
		AWSSessionToken:            "tok",
		AWSSessionTokenPlaceholder: "tokph",
		GitHubAppID:                1234,
	}
	c.Zero()
	if c.AWSAccessKeyID != "" || c.AWSAccessKeyIDPlaceholder != "" ||
		c.AWSSessionToken != "" || c.AWSSessionTokenPlaceholder != "" ||
		c.Scheme != "" {
		t.Fatalf("Zero did not clear aws/scheme: %+v", c)
	}
	if c.GitHubAppID != 1234 {
		t.Errorf("Zero cleared non-secret GitHubAppID")
	}
}

func TestCredentialJSONBackwardCompat(t *testing.T) {
	// Old on-disk format had no Username / UsernamePlaceholder fields.
	oldJSON := `{"id":"x","name":"n","real":"r","placeholder":"p","source":"manual","created_at":"2024-01-01T00:00:00Z"}`
	var got Credential
	if err := json.Unmarshal([]byte(oldJSON), &got); err != nil {
		t.Fatalf("unmarshal old format: %v", err)
	}
	if got.Username != "" || got.UsernamePlaceholder != "" {
		t.Errorf("expected empty basic fields on old record, got %+v", got)
	}
}
