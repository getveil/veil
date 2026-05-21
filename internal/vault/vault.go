package vault

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/getveil/veil/internal/config"
	"github.com/getveil/veil/internal/placeholder"
)

// vaultMeta is the on-disk JSON written to vault.meta. Pre-v1 builds also
// wrote a `vaulted_files` registry tracking every .env path init touched;
// the field is gone after the launch cuts but `json.Unmarshal` silently
// ignores it on load, so existing on-disk meta files still parse cleanly.
type vaultMeta struct {
	ProjectID string `json:"project_id"`
	Version   int    `json:"version"`
}

// Vault is an in-memory representation of an opened vault.
type Vault struct {
	root        string
	projectID   string
	credentials []*Credential
	keystore    Keystore
	// dryRun, when true, makes Save() a no-op so dry-run flows can exercise
	// Add() (and its duplicate/collision checks) without touching disk or
	// the keystore.
	dryRun bool
}

// Open reads and decrypts an existing vault from disk. Both vault.meta and
// vault.bin are read via ReadFileNoFollow so a same-UID adversary who plants
// a symlink at either path can't redirect Veil into reading an attacker-
// chosen project_id (which would steer keystore lookups) or attacker-chosen
// ciphertext.
func Open(root string, ks Keystore) (*Vault, error) {
	metaPath := config.VaultMetaFile(root)
	metaData, err := ReadFileNoFollow(metaPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read meta file: %w", ErrOpen, err)
	}

	var meta vaultMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("%w: invalid meta file: %w", ErrOpen, err)
	}

	vaultPath := config.VaultFile(root)
	blob, err := ReadFileNoFollow(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("%w: read vault file: %w", ErrOpen, err)
	}

	key, err := ks.Get(meta.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	plaintext, err := Unseal(key, blob)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt or truncated vault file (unseal failed): %w", ErrCorrupt, err)
	}

	creds, err := decodeCredentials(plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: corrupt credential data: %w", ErrCorrupt, err)
	}

	return &Vault{
		root:        root,
		projectID:   meta.ProjectID,
		credentials: creds,
		keystore:    ks,
	}, nil
}

// decodeCredentials unmarshals the vault's plaintext blob into a slice of
// Credentials, after pre-filtering any records whose JSON carries a
// `"scheme"` field naming a Veil-pre-v1 scheme (aws / github_app / basic —
// removed in the launch cuts).
//
// Vault on-disk compat choice: rationale for the raw-JSON pre-filter.
//
// The Credential struct has no Scheme field as of Phase 9 (item 5). Without
// pre-filtering, Go's encoding/json silently drops the unknown `scheme`
// field — stale aws/basic/github_app records would load AS Bearer
// placeholders, and the proxy would happily inject their (incorrect for
// the original scheme) `real` values into outbound requests to whatever
// host scope they happen to carry. That's garbage-injection on legacy
// vaults that the v0.1.x install never intended.
//
// The pre-filter inspects each array element's raw JSON for the literal
// pattern `"scheme":"aws"` (or basic / github_app) before unmarshaling,
// and drops those elements. Survivors unmarshal cleanly into the Scheme-
// less Credential struct via Go's tolerant unknown-field handling. The
// dropped records are still on disk and will be left alone until the
// user runs `veil init --force` or `veil remove`.
func decodeCredentials(plaintext []byte) ([]*Credential, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal(plaintext, &raw); err != nil {
		return nil, err
	}
	creds := make([]*Credential, 0, len(raw))
	for _, elem := range raw {
		if rawCredentialHasUnsupportedScheme(elem) {
			continue
		}
		var c Credential
		if err := json.Unmarshal(elem, &c); err != nil {
			return nil, err
		}
		creds = append(creds, &c)
	}
	return creds, nil
}

// rawCredentialHasUnsupportedScheme reports whether elem's JSON has a
// `scheme` field set to one of the v0.1.x schemes the launch cuts dropped.
// Uses a thin probe struct (rather than full unmarshal) so the check stays
// independent of the live Credential struct's field set.
func rawCredentialHasUnsupportedScheme(elem json.RawMessage) bool {
	var probe struct {
		Scheme string `json:"scheme"`
	}
	if err := json.Unmarshal(elem, &probe); err != nil {
		return false
	}
	switch probe.Scheme {
	case "aws", "github_app", "basic":
		return true
	}
	return false
}

// Save encrypts and atomically writes the vault to disk. When the vault was
// constructed with NewInMemoryVault (dry-run mode), Save is a no-op.
func (v *Vault) Save() error {
	if v.dryRun {
		return nil
	}
	data, err := json.Marshal(v.credentials)
	if err != nil {
		return fmt.Errorf("%w: marshal credentials: %w", ErrSave, err)
	}

	key, err := v.keystore.Get(v.projectID)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	blob, err := Seal(key, data)
	if err != nil {
		return fmt.Errorf("%w: seal: %w", ErrSave, err)
	}

	vaultPath := config.VaultFile(v.root)
	backupPath := config.VaultBackupFile(v.root)

	// Backup current vault.bin before overwriting (best-effort).
	if _, err := os.Stat(vaultPath); err == nil {
		_ = copyFile(vaultPath, backupPath)
	}

	// Atomic write: temp file + rename. This pattern is intentionally NOT
	// migrated to WriteFileNoFollow — vault.bin is the most critical file
	// in the system and Sync+Rename gives torn-write crash safety that
	// WriteFileNoFollow does not. The H9 holes don't apply here: CreateTemp
	// uses a random suffix so the tmp path can't be symlink-pre-planted, and
	// POSIX rename(2) replaces a symlink at vaultPath with the renamed file
	// itself rather than following it. Mode lands at 0600 (CreateTemp) and
	// transfers to vaultPath on rename, discarding any prior widened perms.
	dir := filepath.Dir(vaultPath)
	tmp, err := os.CreateTemp(dir, "vault-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: create temp file: %w", ErrSave, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: write temp file: %w", ErrSave, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: sync failed: %w", ErrSave, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: close temp file: %w", ErrSave, err)
	}
	if err := os.Rename(tmpName, vaultPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: atomic rename: %w", ErrSave, err)
	}
	return nil
}

// Add appends a credential after checking for duplicate names and placeholder
// collisions. It persists the vault on success.
func (v *Vault) Add(cred *Credential) error {
	for _, c := range v.credentials {
		if c.Name == cred.Name {
			return fmt.Errorf("%w: %q", ErrDuplicateCredential, cred.Name)
		}
		if collidesWithAny(cred.Placeholder, c) {
			return fmt.Errorf("%w: generated placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", ErrPlaceholderCollision, cred.Name, c.Name)
		}
	}
	v.credentials = append(v.credentials, cred)
	return v.Save()
}

// AddBatch validates all credentials up front and, on success, persists them
// in a single Save. Either every credential is committed or none are.
func (v *Vault) AddBatch(creds []*Credential) error {
	if len(creds) == 0 {
		return nil
	}

	// Existing-name and existing-placeholder sets, built from current vault.
	existingNames := make(map[string]struct{}, len(v.credentials))
	existingPHs := make(map[string]string, len(v.credentials)) // ph -> owner name
	for _, c := range v.credentials {
		existingNames[c.Name] = struct{}{}
		if c.Placeholder != "" {
			existingPHs[c.Placeholder] = c.Name
		}
	}

	// Within-batch sets so duplicates inside creds[] are caught too.
	batchNames := make(map[string]struct{}, len(creds))
	batchPHs := make(map[string]string, len(creds))

	for _, cred := range creds {
		if _, ok := existingNames[cred.Name]; ok {
			return fmt.Errorf("%w: %q", ErrDuplicateCredential, cred.Name)
		}
		if _, ok := batchNames[cred.Name]; ok {
			return fmt.Errorf("%w: %q (duplicate within batch)", ErrDuplicateCredential, cred.Name)
		}
		if cred.Placeholder != "" {
			if owner, ok := existingPHs[cred.Placeholder]; ok {
				return fmt.Errorf("%w: generated placeholder for %q matches credential %q. Remove the conflicting credential with veil remove", ErrPlaceholderCollision, cred.Name, owner)
			}
			if owner, ok := batchPHs[cred.Placeholder]; ok {
				return fmt.Errorf("%w: generated placeholder for %q matches credential %q within batch", ErrPlaceholderCollision, cred.Name, owner)
			}
		}
		batchNames[cred.Name] = struct{}{}
		if cred.Placeholder != "" {
			batchPHs[cred.Placeholder] = cred.Name
		}
	}

	preLen := len(v.credentials)
	v.credentials = append(v.credentials, creds...)
	if err := v.Save(); err != nil {
		v.credentials = v.credentials[:preLen]
		return err
	}
	return nil
}

// HasCredential reports whether a credential with name is present.
func (v *Vault) HasCredential(name string) bool {
	_, ok := v.Get(name)
	return ok
}

// collidesWithAny reports whether candidate matches the secret placeholder of c.
func collidesWithAny(candidate string, c *Credential) bool {
	if candidate == "" {
		return false
	}
	return candidate == c.Placeholder
}

// Get finds a credential by name.
func (v *Vault) Get(name string) (*Credential, bool) {
	for _, c := range v.credentials {
		if c.Name == name {
			return c, true
		}
	}
	return nil, false
}

// List returns a copy of all credentials.
func (v *Vault) List() []*Credential {
	out := make([]*Credential, len(v.credentials))
	copy(out, v.credentials)
	return out
}

// Names returns the names of all loaded credentials. The order matches
// insertion order. Used by the runner to identify shell-exported env vars
// that must be stripped before invoking the child process.
func (v *Vault) Names() []string {
	out := make([]string, 0, len(v.credentials))
	for _, c := range v.credentials {
		out = append(out, c.Name)
	}
	return out
}

// Delete removes a credential by name and persists the vault.
// Returns (false, nil) if the credential was not found.
func (v *Vault) Delete(name string) (bool, error) {
	for i, c := range v.credentials {
		if c.Name == name {
			v.credentials = append(v.credentials[:i], v.credentials[i+1:]...)
			if err := v.Save(); err != nil {
				return true, err
			}
			return true, nil
		}
	}
	return false, nil
}

// Credentials is an alias for List.
func (v *Vault) Credentials() []*Credential {
	return v.List()
}

// PlaceholderSet returns the set of currently-used placeholder strings,
// suitable for passing to placeholder.Generate to prevent collisions.
func (v *Vault) PlaceholderSet() placeholder.Set {
	out := make(placeholder.Set, len(v.credentials))
	for _, c := range v.credentials {
		if c.Placeholder != "" {
			out[c.Placeholder] = struct{}{}
		}
	}
	return out
}

// PlaceholderMap returns a map from placeholder value to credential, used by
// the injector to swap placeholders back to real secrets.
func (v *Vault) PlaceholderMap() map[string]*Credential {
	m := make(map[string]*Credential, len(v.credentials))
	for _, c := range v.credentials {
		c := c
		if c.Placeholder != "" {
			m[c.Placeholder] = c
		}
	}
	return m
}

// ProjectID returns the vault's project identifier.
func (v *Vault) ProjectID() string {
	return v.projectID
}

// NewInMemoryVault returns a Vault that lives entirely in memory: no .veil/
// directory, no meta file, no keystore entry, no encrypted blob on disk.
// Save() is a no-op so callers can exercise Add() (with its duplicate and
// placeholder-collision checks) for dry-run previews. The returned vault
// must not be re-opened later — it has no on-disk presence.
func NewInMemoryVault(root, projectID string) *Vault {
	return &Vault{
		root:        root,
		projectID:   projectID,
		credentials: []*Credential{},
		keystore:    NewMemKeystore(),
		dryRun:      true,
	}
}

// CreateVault initialises a new vault on disk: creates .veil/, vault.meta,
// generates a master key, stores it in the keystore, and writes an empty
// encrypted vault.
//
// CreateVault refuses to operate if .veil/ already exists as a symlink.
// Without this gate, EnsureDir's MkdirAll is a no-op against the link target
// and the subsequent Chmod would tighten the target's perms — a same-UID
// adversary who plants .veil/ → ~/.config (or similar) can both deface
// unrelated state and steer all subsequent .veil/ writes into the attacker-
// chosen directory. Mirrors audit.Open's parent-dir preflight.
func CreateVault(root string, projectID string, ks Keystore) (*Vault, error) {
	stateDir := config.ProjectStateDir(root)
	if info, err := os.Lstat(stateDir); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: state dir is a symlink: %s", ErrSave, stateDir)
	}
	if err := config.EnsureDir(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("%w: create state dir: %w", ErrSave, err)
	}

	// Write vault.meta.
	meta := vaultMeta{ProjectID: projectID, Version: 1}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal meta: %w", ErrSave, err)
	}
	if err := WriteFileNoFollow(config.VaultMetaFile(root), metaBytes, 0600); err != nil {
		return nil, fmt.Errorf("%w: write meta: %w", ErrSave, err)
	}

	// Generate master key.
	var key [32]byte
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, fmt.Errorf("%w: generate key: %w", ErrSave, err)
	}
	if err := ks.Set(projectID, key); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMasterKey, err)
	}

	v := &Vault{
		root:        root,
		projectID:   projectID,
		credentials: []*Credential{},
		keystore:    ks,
	}

	if err := v.Save(); err != nil {
		return nil, err
	}

	// Write .gitignore inside .veil/ so nothing is accidentally committed.
	gitignorePath := config.VaultGitignoreFile(root)
	if err := WriteFileNoFollow(gitignorePath, []byte("*\n"), 0600); err != nil {
		return nil, fmt.Errorf("%w: write gitignore: %w", ErrSave, err)
	}

	return v, nil
}

// copyFile copies src to dst, overwriting dst if it exists. Both legs use
// O_NOFOLLOW so a pre-planted symlink at src can't pull attacker-chosen file
// contents (e.g. ~/.ssh/id_rsa) into the destination, and a pre-planted
// symlink at dst can't redirect the bytes to an attacker-chosen target. dst
// also lands at 0600 even if a previous install left it world-readable.
func copyFile(src, dst string) error {
	data, err := ReadFileNoFollow(src)
	if err != nil {
		return err
	}
	return WriteFileNoFollow(filepath.Clean(dst), data, 0600)
}
