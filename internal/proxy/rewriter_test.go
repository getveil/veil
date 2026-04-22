package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// TestRewriter_NoCrossContamination asserts that the injector's rewriter does
// not re-scan replaced bytes. If placeholder A's real value happens to contain
// placeholder B's pattern, B must not be replaced inside A's real after A's
// swap — the matching has to operate on the original input only.
//
// The bug this test guards against (SEC-7): the previous implementation did
// strings.ReplaceAll per matched placeholder in non-deterministic map order.
// When A was processed before B and A.Real contained B.Placeholder, the
// subsequent strings.ReplaceAll for B would clobber the freshly-injected
// secret with B.Real, silently corrupting the outbound request.
func TestRewriter_NoCrossContamination(t *testing.T) {
	credA := makeCred("alpha",
		"VEIL_PLACEHOLDER_A_1111",                // placeholder A
		"real-alpha_VEIL_PLACEHOLDER_B_2222_tail", // real A *contains* placeholder B
		"api.example.com",
	)
	credB := makeCred("bravo",
		"VEIL_PLACEHOLDER_B_2222",
		"real-bravo",
		"api.example.com",
	)

	// Map iteration order in Go is randomized. Run many iterations to
	// catch any ordering under which the old code would have corrupted A.
	for i := 0; i < 50; i++ {
		inj := NewInjector(placeholderMap(credA, credB), nil, 1, "test")

		rawURL := "https://api.example.com/v1"
		hdr := http.Header{}
		hdr.Set("Authorization", "Bearer VEIL_PLACEHOLDER_A_1111 and VEIL_PLACEHOLDER_B_2222")
		body := []byte("payload=VEIL_PLACEHOLDER_A_1111,other=VEIL_PLACEHOLDER_B_2222")

		_, newHeader, newBody, _ := inj.ProcessRequest("req-xc", "POST", rawURL, hdr, body)

		// Exactly the two placeholders must be swapped for exactly their
		// respective real values. A's real must survive intact — if B's
		// substitution ran on the rewritten bytes, "VEIL_PLACEHOLDER_B_2222"
		// inside A's real would become "real-bravo" and A's real would be
		// corrupted to "real-alpha_real-bravo_tail".
		wantAuth := "Bearer real-alpha_VEIL_PLACEHOLDER_B_2222_tail and real-bravo"
		if got := newHeader.Get("Authorization"); got != wantAuth {
			t.Fatalf("iter %d: header Authorization = %q, want %q", i, got, wantAuth)
		}

		wantBody := "payload=real-alpha_VEIL_PLACEHOLDER_B_2222_tail,other=real-bravo"
		if got := string(newBody); got != wantBody {
			t.Fatalf("iter %d: body = %q, want %q", i, got, wantBody)
		}
	}
}

// TestRewriter_OverlappingPatternsAtSamePosition asserts the rewriter picks
// the longest pattern at a given start position, so a shorter placeholder
// that is a substring of a longer one does not pre-empt the longer match.
func TestRewriter_OverlappingPatternsAtSamePosition(t *testing.T) {
	credShort := makeCred("short", "VEIL_FOO", "short-real", "api.example.com")
	credLong := makeCred("long", "VEIL_FOO_BAR", "long-real", "api.example.com")

	for i := 0; i < 50; i++ {
		inj := NewInjector(placeholderMap(credShort, credLong), nil, 1, "test")

		body := []byte("x=VEIL_FOO_BAR y=VEIL_FOO z=end")
		_, _, newBody, _ := inj.ProcessRequest("req-over", "POST",
			"https://api.example.com/v1", http.Header{}, body)

		// The long pattern at position 2 wins over the short pattern at
		// position 2. The isolated VEIL_FOO at position 19 still swaps.
		want := "x=long-real y=short-real z=end"
		if got := string(newBody); got != want {
			t.Fatalf("iter %d: body = %q, want %q", i, got, want)
		}
	}
}

// TestRewriter_URLAlsoUsesSinglePass covers the URL code path; the ordering
// bug lived there too (injector.go:118 prior to the fix).
func TestRewriter_URLAlsoUsesSinglePass(t *testing.T) {
	credA := makeCred("alpha", "VEIL_PH_A",
		"realA_VEIL_PH_B_embedded", "api.example.com")
	credB := makeCred("bravo", "VEIL_PH_B", "realB", "api.example.com")

	for i := 0; i < 50; i++ {
		inj := NewInjector(placeholderMap(credA, credB), nil, 1, "test")

		rawURL := "https://api.example.com/v1?a=VEIL_PH_A&b=VEIL_PH_B"
		newURL, _, _, _ := inj.ProcessRequest("req-url", "GET", rawURL,
			http.Header{}, nil)

		want := "https://api.example.com/v1?a=realA_VEIL_PH_B_embedded&b=realB"
		if newURL != want {
			t.Fatalf("iter %d: URL = %q, want %q", i, newURL, want)
		}
		// And the URL must not re-inject B's pattern inside A's real.
		if strings.Contains(newURL, "realA_realB_embedded") {
			t.Fatalf("iter %d: cross-contamination detected: %s", i, newURL)
		}
	}
}
