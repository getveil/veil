package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/8enji/veil/internal/vault"
)

func genPEM(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return key, string(pem.EncodeToMemory(block))
}

// signJWT produces an RS256 JWT using the given RSA private key and iss
// claim. The hash constant (crypto.SHA256) is the RFC 7518 §3.3 form: the
// signature is over the SHA-256 digest of the signing input and carries a
// DigestInfo prefix.
func signJWT(t *testing.T, key *rsa.PrivateKey, iss int64) string {
	t.Helper()
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := `{"iss":` + strconv.FormatInt(iss, 10) + `,"iat":1700000000,"exp":1700000600}`
	input := base64URLEncode([]byte(header)) + "." + base64URLEncode([]byte(payload))
	h := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64URLEncode(sig)
}

func TestSignGitHubAppJWT_HappyPath(t *testing.T) {
	realKey, realPEM := genPEM(t)
	placeholderKey, placeholderPEM := genPEM(t)

	cred := &vault.Credential{
		ID:           "c1",
		Name:         "gh-app",
		Scheme:       "github_app",
		Real:         realPEM,
		Placeholder:  placeholderPEM,
		GitHubAppID:  123456,
		AllowedHosts: []string{"api.github.com"},
	}
	creds := map[string]*vault.Credential{placeholderPEM: cred}

	// Agent signs a JWT with the placeholder key.
	jwt := signJWT(t, placeholderKey, 123456)
	req, _ := http.NewRequest("POST", "https://api.github.com/app/installations", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	inj, outcome := signGitHubAppJWT(req, creds, "api.github.com")
	if outcome != LocationGitHubAppJWTResigned {
		t.Fatalf("outcome = %q", outcome)
	}

	// Verify the new JWT verifies against the real key.
	newJWT := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(newJWT, ".")
	if len(parts) != 3 {
		t.Fatalf("new JWT not 3-part: %s", newJWT)
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64URLDecode(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(&realKey.PublicKey, crypto.SHA256, h[:], sig); err != nil {
		t.Errorf("new JWT does not verify with real key: %v", err)
	}
	_ = placeholderKey
	if len(inj) != 1 || inj[0].Location != LocationGitHubAppJWTResigned {
		t.Errorf("injections = %+v", inj)
	}
}

func TestSignGitHubAppJWT_UnknownIssFailsClosed(t *testing.T) {
	_, placeholderPEM := genPEM(t)
	key, _ := genPEM(t) // Use a different key so we don't actually need the real one
	cred := &vault.Credential{
		Scheme:       "github_app",
		Real:         placeholderPEM,
		Placeholder:  placeholderPEM,
		GitHubAppID:  111,
		AllowedHosts: []string{"api.github.com"},
	}
	creds := map[string]*vault.Credential{placeholderPEM: cred}
	jwt := signJWT(t, key, 999) // iss does not match GitHubAppID

	req, _ := http.NewRequest("POST", "https://api.github.com/", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)

	inj, outcome := signGitHubAppJWT(req, creds, "api.github.com")
	if outcome != LocationSignerFailed {
		t.Fatalf("outcome = %q", outcome)
	}
	if inj[0].SignerError != SignerErrUnknownGitHubAppID {
		t.Errorf("SignerError = %q", inj[0].SignerError)
	}
}

func TestSignGitHubAppJWT_PATIgnored(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer ghp_1234567890abcdef")
	_, outcome := signGitHubAppJWT(req, map[string]*vault.Credential{}, "api.github.com")
	if outcome != "" {
		t.Errorf("outcome should be empty for PAT, got %q", outcome)
	}
}

func TestSignGitHubAppJWT_NoCredentialForHost_Unmediated(t *testing.T) {
	key, _ := genPEM(t)
	jwt := signJWT(t, key, 42)
	req, _ := http.NewRequest("GET", "https://api.github.com/app", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	// Empty credential map: no github_app cred covers this host.
	_, outcome := signGitHubAppJWT(req, map[string]*vault.Credential{}, "api.github.com")
	if outcome != LocationSchemeUnmediated {
		t.Errorf("outcome = %q", outcome)
	}
}
