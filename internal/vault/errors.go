package vault

import "errors"

// Sentinel errors returned by the vault package. Wrap with fmt.Errorf using
// the %w verb so callers can match via errors.Is.
var (
	// ErrOpen indicates the vault could not be opened (read meta, read blob,
	// decrypt, or unmarshal failed).
	ErrOpen = errors.New("vault: open failed")

	// ErrMasterKey indicates the master key could not be retrieved from the
	// keystore.
	ErrMasterKey = errors.New("vault: master key retrieval failed")

	// ErrCorrupt indicates the on-disk vault data is corrupt or truncated.
	ErrCorrupt = errors.New("vault: corrupt data")

	// ErrDuplicateCredential indicates Add was called with a name that already
	// exists.
	ErrDuplicateCredential = errors.New("vault: duplicate credential name")

	// ErrPlaceholderCollision indicates Add was called with a placeholder that
	// collides with an existing credential. Upstream generator should retry
	// before surfacing this.
	ErrPlaceholderCollision = errors.New("vault: placeholder collision")

	// ErrSave indicates the vault could not be persisted (marshal, encrypt,
	// or atomic write failed).
	ErrSave = errors.New("vault: save failed")

	// ErrKeystoreUnavailable indicates the system keystore (keyring, file)
	// could not be reached. Use ErrPassphraseMissing for the narrower case
	// where the file-backed fallback has no passphrase configured — the two
	// require different user-facing remediation.
	ErrKeystoreUnavailable = errors.New("keystore: unavailable")

	// ErrPassphraseMissing indicates VEIL_PASSPHRASE is unset for the
	// file-backed keystore fallback. Distinct from ErrKeystoreUnavailable so
	// the CLI can tell the user to set the env var instead of routing them to
	// the destructive `veil init --force` recovery path.
	ErrPassphraseMissing = errors.New("keystore: passphrase missing")

	// ErrKeystoreWrite indicates a write or chmod on the keystore backing
	// store failed.
	ErrKeystoreWrite = errors.New("keystore: write failed")
)
