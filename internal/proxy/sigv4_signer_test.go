package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/getveil/veil/internal/vault"
)

func TestCanonicalURI(t *testing.T) {
	cases := []struct {
		name, in, want string
		isS3           bool
	}{
		{"root path", "/", "/", false},
		{"normal path", "/foo/bar", "/foo/bar", false},
		{"percent-encoded reserved", "/a b", "/a%20b", false},
		{"s3 preserves double slash", "/foo//bar", "/foo//bar", true},
		{"non-s3 collapses double slash", "/foo//bar", "/foo/bar", false},
		{"dot segments collapsed non-s3", "/foo/./bar/..", "/foo/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalURI(tc.in, tc.isS3)
			if got != tc.want {
				t.Errorf("canonicalURI(%q, s3=%v) = %q, want %q", tc.in, tc.isS3, got, tc.want)
			}
		})
	}
}

func TestCanonicalQueryString(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single", "foo=bar", "foo=bar"},
		{"sort by name", "b=2&a=1", "a=1&b=2"},
		{"same name sort by value", "a=2&a=1", "a=1&a=2"},
		{"empty value keeps =", "a=", "a="},
		{"encode space", "a=1 2", "a=1%202"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalQueryString(tc.in)
			if got != tc.want {
				t.Errorf("canonicalQueryString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSigV4Authorization(t *testing.T) {
	value := "AWS4-HMAC-SHA256 " +
		"Credential=AKIAIOSFODNN7REDACTD/20150830/us-east-1/iam/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	got, err := parseSigV4Authorization(value)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.AccessKeyID != "AKIAIOSFODNN7REDACTD" {
		t.Errorf("AccessKeyID = %q", got.AccessKeyID)
	}
	if got.Date != "20150830" || got.Region != "us-east-1" || got.Service != "iam" {
		t.Errorf("scope wrong: %+v", got)
	}
	if len(got.SignedHeaders) != 3 || got.SignedHeaders[0] != "content-type" {
		t.Errorf("SignedHeaders = %v", got.SignedHeaders)
	}
	if got.Signature == "" {
		t.Error("Signature empty")
	}
}

func TestParseSigV4Authorization_Malformed(t *testing.T) {
	cases := []string{
		"",
		"Bearer foo",
		"AWS4-HMAC-SHA256 Credential=missing-slashes",
		"AWS4-HMAC-SHA256 SignedHeaders=host, Signature=xx", // no Credential
	}
	for _, c := range cases {
		if _, err := parseSigV4Authorization(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

// AWS SigV4 signing-key derivation test vector, published at:
// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
// The secret value is AWS's documented example — required for the published
// hash to match. The placeholder stub-value denylist does not apply here:
// this test calls deriveSigningKey directly, not IsSecretLike.
func TestDeriveSigningKey_PublishedVector(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"
	key := deriveSigningKey(secret, date, region, service)
	got := fmt.Sprintf("%x", key)
	want := "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
	if got != want {
		t.Errorf("deriveSigningKey = %s, want %s", got, want)
	}
}

func TestCanonicalHeaders(t *testing.T) {
	hdr := map[string][]string{
		"Host":         {"s3.amazonaws.com"},
		"X-Amz-Date":   {"20150830T123600Z"},
		"Content-Type": {"  application/json   "},
	}
	signed := []string{"host", "x-amz-date", "content-type"}
	got := canonicalHeaders(hdr, signed)
	want := "host:s3.amazonaws.com\nx-amz-date:20150830T123600Z\ncontent-type:application/json\n"
	if got != want {
		t.Errorf("canonicalHeaders mismatch:\n got=%q\nwant=%q", got, want)
	}
}

// From AWS SigV4 test suite "get-vanilla":
// https://github.com/aws-samples/sigv4-test-suite
// Values are AWS's documented vector — required for the published signature
// to match. The placeholder stub-value denylist does not apply here:
// this test calls signAWSSigV4 directly, not IsSecretLike.
func TestSignAWSSigV4_GetVanilla(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	akid := "AKIDEXAMPLE"
	date := "20150830T123600Z"

	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Header.Set("Host", "example.amazonaws.com")
	req.Header.Set("X-Amz-Date", date)
	// Initial Authorization uses a placeholder signature; signer replaces it.
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 "+
			"Credential="+akid+"/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=host;x-amz-date, "+
			"Signature=ignored")

	cred := &vault.Credential{
		Scheme:                    "aws",
		AWSAccessKeyID:            akid,
		AWSAccessKeyIDPlaceholder: akid,
		Real:                      secret,
		Placeholder:               "VeilPH",
		AllowedHosts:              []string{"*.amazonaws.com"},
	}
	body := []byte{}
	injections, outcome := signAWSSigV4(req, body, map[string]*vault.Credential{akid: cred}, "example.amazonaws.com")
	if outcome != LocationAWSSigV4Resigned {
		t.Fatalf("outcome = %q, want aws_sigv4_resigned", outcome)
	}
	got := req.Header.Get("Authorization")
	wantSig := "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if !strings.Contains(got, "Signature="+wantSig) {
		t.Errorf("signature mismatch.\n got=%s\n want suffix=Signature=%s", got, wantSig)
	}
	if len(injections) != 1 || injections[0].Location != LocationAWSSigV4Resigned {
		t.Errorf("injections = %+v", injections)
	}
}

func TestSignAWSSigV4_UnknownKeyFailsClosed(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Header.Set("Host", "example.amazonaws.com")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIAUNKNOWN/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=host, Signature=xx")

	cred := &vault.Credential{
		Scheme:                    "aws",
		AWSAccessKeyID:            "AKIAREAL",
		AWSAccessKeyIDPlaceholder: "AKIAOTHER",
		Real:                      "secret",
		AllowedHosts:              []string{"*.amazonaws.com"},
	}
	inj, outcome := signAWSSigV4(req, nil, map[string]*vault.Credential{"AKIAOTHER": cred}, "example.amazonaws.com")
	if outcome != LocationSignerFailed {
		t.Fatalf("outcome = %q, want signer_failed", outcome)
	}
	if inj[0].SignerError != SignerErrUnknownAccessKeyID {
		t.Errorf("SignerError = %q", inj[0].SignerError)
	}
}

func TestSignAWSSigV4_NoCredentialForHost_Unmediated(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.amazonaws.com/", nil)
	req.Header.Set("Host", "example.amazonaws.com")
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("Authorization",
		"AWS4-HMAC-SHA256 Credential=AKIANO/20150830/us-east-1/service/aws4_request, "+
			"SignedHeaders=host, Signature=xx")
	// Empty credential map: nothing covers this host.
	inj, outcome := signAWSSigV4(req, nil, map[string]*vault.Credential{}, "example.amazonaws.com")
	if outcome != LocationSchemeUnmediated {
		t.Errorf("outcome = %q, want scheme_unmediated", outcome)
	}
	if len(inj) != 0 {
		t.Errorf("expected no injections for unmediated, got %+v", inj)
	}
}
