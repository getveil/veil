package vault

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Credential holds a single secret and its proxy placeholder.
//
// On-disk compat: older v0.1.x vaults may contain records with extra
// fields (Scheme="aws"/"github_app"/"basic", aws_access_key_id,
// github_app_id, username, etc.). Go's encoding/json silently ignores
// unknown fields on a struct so those records still load, but the
// raw-JSON pre-filter inside `decodeCredentials` drops aws /
// github_app / basic records BEFORE unmarshal — otherwise their `real`
// values would silently load as Bearer placeholders and the proxy would
// inject them into outbound requests against whatever host scope they
// happen to carry.
type Credential struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Real         string    `json:"real"`
	Placeholder  string    `json:"placeholder"`
	Source       string    `json:"source"`
	AllowedHosts []string  `json:"allowed_hosts,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
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
}

// NewID generates a ULID suitable for use as a credential identifier.
func NewID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
