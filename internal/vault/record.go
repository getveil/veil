package vault

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
)

// Credential holds a single secret and its proxy placeholder.
type Credential struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Real        string    `json:"real"`
	Placeholder string    `json:"placeholder"`
	Source      string    `json:"source"`
	CreatedAt   time.Time `json:"created_at"`
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
