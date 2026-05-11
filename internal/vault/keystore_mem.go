package vault

import "fmt"

// MemKeystore is an in-memory Keystore for tests.
type MemKeystore struct {
	keys map[string][32]byte
}

// NewMemKeystore returns an empty MemKeystore.
func NewMemKeystore() *MemKeystore {
	return &MemKeystore{keys: make(map[string][32]byte)}
}

func (m *MemKeystore) Get(projectID string) ([32]byte, error) {
	k, ok := m.keys[KeystoreAccount(projectID)]
	if !ok {
		return [32]byte{}, fmt.Errorf("keystore: no key for project %q", projectID)
	}
	return k, nil
}

func (m *MemKeystore) Set(projectID string, key [32]byte) error {
	m.keys[KeystoreAccount(projectID)] = key
	return nil
}

func (m *MemKeystore) Delete(projectID string) error {
	delete(m.keys, KeystoreAccount(projectID))
	return nil
}

// Accounts returns the keystore-account names of every entry currently held.
// Intended for tests that need to assert the keystore is empty or to detect
// orphaned master-key entries.
func (m *MemKeystore) Accounts() []string {
	out := make([]string, 0, len(m.keys))
	for k := range m.keys {
		out = append(out, k)
	}
	return out
}

// Reset clears all entries. Tests use this between cases that share the
// process-wide singleton MemKeystore.
func (m *MemKeystore) Reset() {
	for k := range m.keys {
		delete(m.keys, k)
	}
}
