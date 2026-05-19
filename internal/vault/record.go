package vault

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Credential holds a single secret and its proxy placeholder.
//
// Note: tolerant JSON unmarshaling. Older vaults written by v0.1.x may
// contain Scheme="aws"/"github_app"/"basic" records with extra fields
// (e.g. aws_access_key_id, github_app_id, username). Go's encoding/json
// silently ignores unknown fields on a struct, so those records still
// load — they will be rendered with whatever subset of the surviving
// fields they happen to have. See `Vault.skipUnsupportedSchemes` for the
// runtime filter that removes them before the proxy can act on them.
type Credential struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Real         string    `json:"real"`
	Placeholder  string    `json:"placeholder"`
	Source       string    `json:"source"`
	AllowedHosts []string  `json:"allowed_hosts,omitempty"`
	CreatedAt    time.Time `json:"created_at"`

	// Scheme is a discriminator: "" (bearer). Older vaults may have
	// "aws"/"github_app"/"basic" records which are filtered out at Open
	// time (see Vault.skipUnsupportedSchemes).
	Scheme string `json:"scheme,omitempty"`
}

// String returns a redacted representation that never leaks secret material.
func (c *Credential) String() string {
	return fmt.Sprintf("Credential{ID:%s, Name:%s}", c.ID, c.Name)
}

// Zero clears sensitive fields. Best-effort for MVP since Go strings are
// immutable; the previous backing memory remains until GC.
func (c *Credential) Zero() {
	c.Real = ""
	c.Placeholder = ""
	c.Scheme = ""
}

// NewID generates a ULID suitable for use as a credential identifier.
func NewID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
