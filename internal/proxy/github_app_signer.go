package proxy

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/getveil/veil/internal/audit"
	"github.com/getveil/veil/internal/placeholder"
	"github.com/getveil/veil/internal/vault"
)

// signGitHubAppJWT inspects the Authorization header for an RS256 JWT with
// an integer `iss` claim matching a vaulted GitHub App credential, and
// re-signs it with the real private key. Returns:
//   - (nil, "")                        → not our scheme (no JWT, malformed,
//     non-RS256 alg, PAT, etc.). Caller continues with other signers.
//   - (failInj, LocationSignerFailed)  → known-host-unknown-iss or RSA
//     sign failure (fail-closed: caller must block the request).
//   - (nil, LocationSchemeUnmediated)  → a GitHub App JWT was seen but no
//     vaulted cred covers this host.
//   - (resignInj, LocationGitHubAppJWTResigned) → re-signed; the
//     Authorization header has been rewritten in place.
func signGitHubAppJWT(req *http.Request, creds map[string]*vault.Credential, host string) ([]audit.Injection, string) {
	auth := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return nil, ""
	}
	token := strings.TrimSpace(auth[len(prefix):])
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ""
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, ""
	}
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, ""
	}
	var headerObj map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &headerObj); err != nil {
		return nil, ""
	}
	if unquote(headerObj["alg"]) != "RS256" || unquote(headerObj["typ"]) != "JWT" {
		return nil, "" // not our scheme
	}

	// Parse iss.
	var payloadObj map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &payloadObj); err != nil {
		return nil, ""
	}
	issRaw, ok := payloadObj["iss"]
	if !ok {
		return nil, ""
	}
	iss, err := parseIssInt(issRaw)
	if err != nil {
		return nil, ""
	}

	// Credential lookup.
	cred := lookupGitHubAppCred(creds, iss, host)
	if cred == nil {
		if veilOwnsGitHubAppHost(creds, host) {
			return []audit.Injection{failInjection(host, req, SignerErrUnknownGitHubAppID)}, LocationSignerFailed
		}
		return nil, LocationSchemeUnmediated
	}

	// Decode the real private key.
	block, _ := pem.Decode([]byte(cred.Real))
	if block == nil {
		return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
	}
	realKey, parseErr := parseRSAPrivateKey(block.Bytes)
	if parseErr != nil {
		return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
	}

	// Re-serialize header/payload deterministically.
	hdrBytes, err := reserializeDeterministic(headerJSON)
	if err != nil {
		hdrBytes = headerJSON
	}
	pldBytes, err := reserializeDeterministic(payloadJSON)
	if err != nil {
		pldBytes = payloadJSON
	}
	signingInput := base64URLEncode(hdrBytes) + "." + base64URLEncode(pldBytes)
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, realKey, crypto.SHA256, h[:])
	if err != nil {
		return []audit.Injection{failInjection(host, req, SignerErrRSASignFailed)}, LocationSignerFailed
	}
	newJWT := signingInput + "." + base64URLEncode(sig)

	beforeLen := len(auth)
	req.Header.Set("Authorization", "Bearer "+newJWT)

	return []audit.Injection{{
		Timestamp:      time.Now(),
		Host:           host,
		CredentialID:   cred.ID,
		CredentialName: cred.Name,
		BytesBefore:    beforeLen,
		BytesAfter:     len("Bearer " + newJWT),
		Location:       LocationGitHubAppJWTResigned,
	}}, LocationGitHubAppJWTResigned
}

// lookupGitHubAppCred scans creds for one whose typed GitHubAppID field
// matches iss AND whose AllowedHosts covers host. Matching on the typed
// field (per spec §131-134) means a corrupted Scheme string cannot cause
// wrong-signer dispatch.
func lookupGitHubAppCred(creds map[string]*vault.Credential, iss int64, host string) *vault.Credential {
	seen := map[*vault.Credential]bool{}
	for _, c := range creds {
		if c == nil || seen[c] || c.GitHubAppID == 0 {
			continue
		}
		seen[c] = true
		if c.GitHubAppID == iss && placeholder.HostMatches(host, c.AllowedHosts) {
			return c
		}
	}
	return nil
}

// veilOwnsGitHubAppHost reports whether any credential in creds carries a
// non-zero GitHubAppID and covers host. Used to decide between fail-closed
// and unmediated when a GitHub App JWT arrives with an iss we can't resolve.
func veilOwnsGitHubAppHost(creds map[string]*vault.Credential, host string) bool {
	seen := map[*vault.Credential]bool{}
	for _, c := range creds {
		if c == nil || seen[c] || c.GitHubAppID == 0 {
			continue
		}
		seen[c] = true
		if placeholder.HostMatches(host, c.AllowedHosts) {
			return true
		}
	}
	return false
}

// unquote extracts a JSON string from a RawMessage, returning "" if the
// value is missing or not a string.
func unquote(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// parseIssInt extracts an integer from a JSON value that is either a number
// or a numeric string. GitHub's own examples show `iss` as an integer;
// older SDKs sometimes serialize it as a string.
func parseIssInt(raw json.RawMessage) (int64, error) {
	var asInt int64
	if err := json.Unmarshal(raw, &asInt); err == nil {
		return asInt, nil
	}
	var asStr string
	if err := json.Unmarshal(raw, &asStr); err == nil {
		return strconv.ParseInt(asStr, 10, 64)
	}
	return 0, errors.New("iss not integer-like")
}

// parseRSAPrivateKey tries PKCS#1, then PKCS#8. Other formats are rejected.
func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is not RSA")
		}
		return rk, nil
	}
	return nil, errors.New("unknown RSA key format")
}
