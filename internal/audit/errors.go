package audit

import "errors"

var (
	// ErrAuditOpen indicates the audit database could not be opened or initialized.
	ErrAuditOpen = errors.New("audit: open failed")

	// ErrAuditWrite indicates a write to the audit database failed.
	ErrAuditWrite = errors.New("audit: write failed")
)
