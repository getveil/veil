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
