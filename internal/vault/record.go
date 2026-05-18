package vault

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Credential holds a single secret and its proxy placeholder.
type Credential struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Real                string   `json:"real"`
	Placeholder         string   `json:"placeholder"`
	Source              string   `json:"source"`
	AllowedHosts        []string `json:"allowed_hosts,omitempty"`
	Username            string   `json:"username,omitempty"`
	UsernamePlaceholder string   `json:"username_placeholder,omitempty"`
	// UsernameVar is the source env-var name for the Username half of a
	// basic credential (set by init when correlating *_USER(NAME) + *_PASS
	// pairs). Persisted so the crash-window recovery path can detect
	// user edits to the username line; empty for manually-added basic
	// creds and for non-basic schemes.
	UsernameVar string    `json:"username_var,omitempty"`
	CreatedAt   time.Time `json:"created_at"`

	// Scheme is a discriminator: "", "basic", "aws", "github_app".
	// Empty means bearer; "basic" is implied when Username != "".
	Scheme string `json:"scheme,omitempty"`

	// AWS SigV4 fields (Scheme == "aws").
	AWSAccessKeyID             string `json:"aws_access_key_id,omitempty"`
	AWSAccessKeyIDPlaceholder  string `json:"aws_access_key_id_placeholder,omitempty"`
	AWSSessionToken            string `json:"aws_session_token,omitempty"`
	AWSSessionTokenPlaceholder string `json:"aws_session_token_placeholder,omitempty"`

	// GitHub App JWT fields (Scheme == "github_app").
	GitHubAppID          int64 `json:"github_app_id,omitempty"`
	GitHubInstallationID int64 `json:"github_installation_id,omitempty"`
}

// String returns a redacted representation that never leaks secret material.
func (c *Credential) String() string {
	return fmt.Sprintf("Credential{ID:%s, Name:%s}", c.ID, c.Name)
}

// Zero clears sensitive fields. Best-effort for MVP since Go strings are
// immutable; the previous backing memory remains until GC. IDs that are not
// secret (e.g. GitHubAppID) are not cleared.
func (c *Credential) Zero() {
	c.Real = ""
	c.Placeholder = ""
	c.Username = ""
	c.UsernamePlaceholder = ""
	c.AWSAccessKeyID = ""
	c.AWSAccessKeyIDPlaceholder = ""
	c.AWSSessionToken = ""
	c.AWSSessionTokenPlaceholder = ""
	c.Scheme = ""
}

// NewID generates a ULID suitable for use as a credential identifier.
func NewID() string {
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}
