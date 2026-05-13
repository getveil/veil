package proxy

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/vault"
)

// FuzzDecodeBasic fuzzes the Basic-auth header decode+swap path with valid
// and adversarial inputs. The placeholder map is fixed across runs so we
// can assert the returned credential identity.
func FuzzDecodeBasic(f *testing.F) {
	cred := &vault.Credential{
		ID:                  "cred-fuzz",
		Name:                "fuzz",
		Real:                "real-secret-value",
		Placeholder:         "VEIL_SECRET_FUZZ",
		Username:            "realuser",
		UsernamePlaceholder: "VEIL_USER_FUZZ",
		AllowedHosts:        []string{"example.com"},
	}
	pmap := map[string]*vault.Credential{
		cred.Placeholder:         cred,
		cred.UsernamePlaceholder: cred,
	}
	expectedNew := "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Real))

	// Valid happy-path seed.
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(cred.UsernamePlaceholder+":"+cred.Placeholder)))

	// Adversarial seeds.
	f.Add("")
	f.Add("Basic ")
	f.Add("Basic !@#$%")                                            // invalid base64
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(""))) // empty payload
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(":")))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("nouser")))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("\x00\x01\x02:\x00\x01\x02"))) // binary
	f.Add("Bearer " + base64.StdEncoding.EncodeToString([]byte("u:p")))                      // wrong scheme
	f.Add("BASIC " + base64.StdEncoding.EncodeToString([]byte(cred.UsernamePlaceholder+":"+cred.Placeholder)))
	f.Add("Basic " + base64.URLEncoding.EncodeToString([]byte(cred.UsernamePlaceholder+":"+cred.Placeholder)))
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Placeholder+":"+cred.UsernamePlaceholder))) // swapped halves
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte(cred.UsernamePlaceholder+":notasecret")))        // partial miss
	f.Add("Basic " + base64.StdEncoding.EncodeToString([]byte("nouser:"+cred.Placeholder)))                    // partial miss

	f.Fuzz(func(t *testing.T, value string) {
		got, newVal, ok := tryRewriteBasic(value, pmap, "example.com")

		if !ok {
			if got != nil {
				t.Fatalf("ok=false but cred != nil: %v", got)
			}
			if newVal != "" {
				t.Fatalf("ok=false but newVal = %q", newVal)
			}
			return
		}

		// ok==true contract:
		if got != cred {
			t.Fatalf("ok=true but returned cred is not the registered one: %+v", got)
		}
		if !strings.HasPrefix(newVal, "Basic ") {
			t.Fatalf("rewritten value must start with 'Basic ': %q", newVal)
		}
		if newVal != expectedNew {
			t.Fatalf("rewritten value = %q, want %q", newVal, expectedNew)
		}
	})
}
