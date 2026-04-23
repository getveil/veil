package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/8enji/veil/internal/audit"
	"github.com/8enji/veil/internal/config"
)

// TestLogCmd_SignerFailedFilter verifies that `veil log --signer-failed`
// returns only rows whose Location == "signer_failed" and renders the
// SignerError column alongside.
func TestLogCmd_SignerFailedFilter(t *testing.T) {
	root := initProject(t)

	// Seed the audit DB with one signer_failed and one ordinary row.
	store, err := audit.Open(config.AuditDBFile(root))
	if err != nil {
		t.Fatalf("audit open: %v", err)
	}
	store.Record(audit.Injection{
		Timestamp:      time.Now(),
		RequestID:      "req-ok",
		Host:           "s3.amazonaws.com",
		Method:         "GET",
		Location:       "aws_sigv4_resigned",
		CredentialName: "aws-prod",
	})
	store.Record(audit.Injection{
		Timestamp:   time.Now(),
		RequestID:   "req-fail",
		Host:        "s3.amazonaws.com",
		Method:      "GET",
		Location:    "signer_failed",
		SignerError: "unknown_access_key_id",
	})
	store.DrainForTest()
	_ = store.Close()

	cmd := NewRoot("test")
	out := new(bytes.Buffer)
	cmd.SetOut(out)
	cmd.SetErr(new(bytes.Buffer))
	cmd.SetArgs([]string{"log", "--path", root, "--signer-failed"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("log --signer-failed: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "signer_failed") {
		t.Errorf("missing 'signer_failed' location in output:\n%s", s)
	}
	if !strings.Contains(s, "unknown_access_key_id") {
		t.Errorf("missing SignerError class in output:\n%s", s)
	}
	if strings.Contains(s, "aws_sigv4_resigned") {
		t.Errorf("--signer-failed should exclude aws_sigv4_resigned, got:\n%s", s)
	}
}
