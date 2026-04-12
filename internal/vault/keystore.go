package vault

// Keystore abstracts master-key persistence. Production implementations use
// the OS keychain; tests use MemKeystore.
type Keystore interface {
	Get(projectID string) ([32]byte, error)
	Set(projectID string, key [32]byte) error
	Delete(projectID string) error
}

// KeystoreAccount returns the canonical account name for a project's master key.
func KeystoreAccount(projectID string) string {
	return "master-key-v1::" + projectID
}
