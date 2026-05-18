package proxy

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/getveil/veil/internal/vault"
)

func basicHeader(user, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
}

func basicCred(name, user, userPH, secret, secretPH string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID:                  "cred-" + name,
		Name:                name,
		Real:                secret,
		Placeholder:         secretPH,
		Username:            user,
		UsernamePlaceholder: userPH,
		AllowedHosts:        hosts,
	}
}

func TestDecodeBasic_HappyPath(t *testing.T) {
	c := basicCred("gh", "johndoe", "VEIL_USER_AAAA", "ghp_real", "VEIL_SECRET_BBBB", "github.com")
	pmap := map[string]*vault.Credential{
		c.Placeholder:         c,
		c.UsernamePlaceholder: c,
	}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER_AAAA", "VEIL_SECRET_BBBB"))

	swaps := decodeAndSwapBasic(hdr, pmap, "github.com")

	if len(swaps) != 1 {
		t.Fatalf("expected 1 swap, got %d", len(swaps))
	}
	if swaps[0].CredentialName != "gh" {
		t.Errorf("swap name = %q", swaps[0].CredentialName)
	}
	if got := hdr.Get("Authorization"); got != basicHeader("johndoe", "ghp_real") {
		t.Errorf("Authorization = %q, want %q", got, basicHeader("johndoe", "ghp_real"))
	}
}

func TestDecodeBasic_ProxyAuthorization(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Proxy-Authorization", basicHeader("VEIL_USER", "VEIL_SECRET"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 1 {
		t.Fatalf("expected 1 swap, got %d", len(swaps))
	}
	if got := hdr.Get("Proxy-Authorization"); got != basicHeader("u", "s") {
		t.Errorf("Proxy-Authorization = %q", got)
	}
}

func TestDecodeBasic_CaseInsensitiveScheme(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	raw := base64.StdEncoding.EncodeToString([]byte("VEIL_USER:VEIL_SECRET"))
	for _, prefix := range []string{"basic ", "BASIC ", "Basic "} {
		hdr := http.Header{}
		hdr.Set("Authorization", prefix+raw)
		swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
		if len(swaps) != 1 {
			t.Errorf("prefix %q: expected 1 swap, got %d", prefix, len(swaps))
		}
	}
}

func TestDecodeBasic_NonBasicSchemeUntouched(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer VEIL_SECRET")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on Bearer header, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != "Bearer VEIL_SECRET" {
		t.Errorf("Bearer header mutated: %q", got)
	}
}

func TestDecodeBasic_MalformedBase64(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Basic !!!not-base64!!!")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on malformed base64, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != "Basic !!!not-base64!!!" {
		t.Errorf("malformed header mutated: %q", got)
	}
}

func TestDecodeBasic_MissingColonInPayload(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("nocolon")))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when payload has no colon, got %d", len(swaps))
	}
}

func TestDecodeBasic_CrossCredentialMixRejected(t *testing.T) {
	a := basicCred("a", "ua", "VEIL_USER_A", "sa", "VEIL_SECRET_A", "example.com")
	b := basicCred("b", "ub", "VEIL_USER_B", "sb", "VEIL_SECRET_B", "example.com")
	pmap := map[string]*vault.Credential{
		a.Placeholder: a, a.UsernamePlaceholder: a,
		b.Placeholder: b, b.UsernamePlaceholder: b,
	}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER_A", "VEIL_SECRET_B"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on cross-credential mix, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != basicHeader("VEIL_USER_A", "VEIL_SECRET_B") {
		t.Errorf("cross-mix header mutated: %q", got)
	}
}

func TestDecodeBasic_EmptyAuthorizationHeader(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", "")

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps on empty Authorization, got %d", len(swaps))
	}
}

func TestDecodeBasic_HostNotAllowed(t *testing.T) {
	c := basicCred("gh", "u", "VEIL_USER", "s", "VEIL_SECRET", "github.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("VEIL_USER", "VEIL_SECRET"))

	swaps := decodeAndSwapBasic(hdr, pmap, "evil.example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when host not in AllowedHosts, got %d", len(swaps))
	}
	if got := hdr.Get("Authorization"); got != basicHeader("VEIL_USER", "VEIL_SECRET") {
		t.Errorf("header should not mutate when host disallowed: %q", got)
	}
}

func TestDecodeBasic_PlaceholderOnlyInSecretHalf(t *testing.T) {
	c := basicCred("gh", "johndoe", "VEIL_USER_X", "ghp_real", "VEIL_SECRET_X", "example.com")
	pmap := map[string]*vault.Credential{c.Placeholder: c, c.UsernamePlaceholder: c}

	hdr := http.Header{}
	hdr.Set("Authorization", basicHeader("someone-else", "VEIL_SECRET_X"))

	swaps := decodeAndSwapBasic(hdr, pmap, "example.com")
	if len(swaps) != 0 {
		t.Errorf("expected 0 swaps when username half does not match, got %d", len(swaps))
	}
}

func TestParseBasicHeader(t *testing.T) {
	cases := []struct {
		name     string
		header   string
		wantUser string
		wantPass string
		wantOK   bool
	}{
		{"happy std encoding", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret")), "alice", "secret", true},
		{"happy url encoding", "Basic " + base64.URLEncoding.EncodeToString([]byte("alice:secret")), "alice", "secret", true},
		{"case-insensitive scheme", "basic " + base64.StdEncoding.EncodeToString([]byte("u:p")), "u", "p", true},
		{"empty", "", "", "", false},
		{"too short", "Basic", "", "", false},
		{"not basic", "Bearer xyz", "", "", false},
		{"malformed base64", "Basic !!!", "", "", false},
		{"missing colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolon")), "", "", false},
		{"empty user empty pass", "Basic " + base64.StdEncoding.EncodeToString([]byte(":")), "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, pass, ok := parseBasicHeader(tc.header)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if user != tc.wantUser {
				t.Errorf("user = %q, want %q", user, tc.wantUser)
			}
			if pass != tc.wantPass {
				t.Errorf("pass = %q, want %q", pass, tc.wantPass)
			}
		})
	}
}
