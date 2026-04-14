package vault

import (
	"io"
	"os"
)

// ProbeWarnWriter is the sink for keyring-probe warnings. Tests swap this to
// capture output.
var ProbeWarnWriter io.Writer = os.Stderr

// NewKeyringKeystoreForTest is the constructor AutoKeystore uses to build the
// keyring implementation. Tests replace it with a stub to drive probe behavior
// without touching the real OS keychain.
var NewKeyringKeystoreForTest = func() Keystore { return NewKeyringKeystore() }
