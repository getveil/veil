package audit

import "errors"

var (
	// ErrOpen indicates the audit database could not be opened or initialized.
	ErrOpen = errors.New("audit: open failed")

	// ErrWrite indicates a write to the audit database failed.
	ErrWrite = errors.New("audit: write failed")
)
