package proxy

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func detectorCred(name string, hosts ...string) *vault.Credential {
	return &vault.Credential{
		ID: "c-" + name, Name: name,
		Real: "r", Placeholder: "VEIL_PH_" + name,
		AllowedHosts: hosts,
	}
}

func buildURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u
}

func TestDetector_FiresOnAuthorizationHeader(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/user")
	hdr := http.Header{}
	hdr.Set("Authorization", "Basic something")

	sig, cNames, fired := detectMismatch("api.github.com", u, hdr, 0, creds)
	if !fired {
		t.Fatal("detector did not fire")
	}
	if sig != authSignalAuthorizationHeader {
		t.Errorf("signal = %q", sig)
	}
	if len(cNames) != 1 || cNames[0] != "gh" {
		t.Errorf("candidate names = %v", cNames)
	}
}

func TestDetector_FiresOnCookie(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	u := buildURL(t, "https://api.example.com/x")
	hdr := http.Header{}
	hdr.Set("Cookie", "session=abc")

	sig, _, fired := detectMismatch("api.example.com", u, hdr, 0, creds)
	if !fired {
		t.Fatal("detector did not fire")
	}
	if sig != authSignalCookie {
		t.Errorf("signal = %q", sig)
	}
}

func TestDetector_FiresOnXTokenHeader(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	u := buildURL(t, "https://api.example.com/x")
	for _, name := range []string{"X-Api-Token", "X-Foo-Key", "X-Custom-Signature", "X-Auth", "x-API-SIG"} {
		hdr := http.Header{}
		hdr.Set(name, "v")
		_, _, fired := detectMismatch("api.example.com", u, hdr, 0, creds)
		if !fired {
			t.Errorf("expected detector to fire for header %q", name)
		}
	}
}

func TestDetector_FiresOnAuthQueryParam(t *testing.T) {
	creds := []*vault.Credential{detectorCred("api", "api.example.com")}
	for _, q := range []string{"auth=x", "signature=x", "sig=x", "token=x", "api_key=x", "apikey=x", "access_token=x"} {
		u := buildURL(t, "https://api.example.com/x?"+q)
		_, _, fired := detectMismatch("api.example.com", u, http.Header{}, 0, creds)
		if !fired {
			t.Errorf("expected detector to fire for query %q", q)
		}
	}
}

func TestDetector_DoesNotFireWhenHostNotMatched(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.openai.com/v1")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.openai.com", u, hdr, 0, creds)
	if fired {
		t.Error("detector fired for non-credentialed host")
	}
}

func TestDetector_DoesNotFireWhenInjected(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.github.com", u, hdr, 1, creds)
	if fired {
		t.Error("detector fired despite injectionCount>0")
	}
}

func TestDetector_DoesNotFireWithoutAuthSignal(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com/zen")
	_, _, fired := detectMismatch("api.github.com", u, http.Header{}, 0, creds)
	if fired {
		t.Error("detector fired with no auth-shaped signal")
	}
}

func TestDetector_HostWithPortMatches(t *testing.T) {
	creds := []*vault.Credential{detectorCred("gh", "api.github.com")}
	u := buildURL(t, "https://api.github.com:443/")
	hdr := http.Header{}
	hdr.Set("Authorization", "Bearer x")

	_, _, fired := detectMismatch("api.github.com:443", u, hdr, 0, creds)
	if !fired {
		t.Error("detector should match host:port against AllowedHosts")
	}
}
