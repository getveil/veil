package correlate

import "regexp"

// twilioAccountSIDRegex captures decoration around the TWILIO_ACCOUNT_SID
// token. Case-sensitive uppercase only — Twilio SDKs read uppercase env
// vars, so loosening case would risk false positives against user-owned
// lowercase names. Anchored at end-of-key so substrings like
// TWILIO_ACCOUNT_SID_REGION don't accidentally match.
var twilioAccountSIDRegex = regexp.MustCompile(`^(.*?)TWILIO_ACCOUNT_SID$`)

// twilioAccountSIDValue mirrors the published Twilio Account SID shape:
// the literal "AC" prefix followed by exactly 32 hex chars. This is the
// same shape that the Twilio provider's Generate produces, so a re-run
// after vaulting won't pair the placeholder. The strict shape gate keeps
// stub values (e.g., TWILIO_ACCOUNT_SID=replace_me) out of the correlator;
// they fall through to placeholder.IsSecretLike, which already rejects
// stubs via isStubValue.
var twilioAccountSIDValue = regexp.MustCompile(`^AC[0-9a-fA-F]{32}$`)

// twilioCorrelator pairs a Twilio Account SID with its Auth Token using
// strict decoration matching on the *_ACCOUNT_SID / *_AUTH_TOKEN suffix.
// The resulting Group is emitted with Scheme=="basic" so the existing
// init_phases.go "case basic:" vault path stores both halves under one
// vault credential — the Twilio Go/Python/Node SDKs all send
// `Authorization: Basic base64(SID:TOKEN)`, so the proxy's tryRewriteBasic
// can swap the placeholder pair back to the real pair in one shot.
//
// Why a provider-specific correlator: the generic basicCorrelator pairs
// USER/USERNAME against PASSWORD/PASS. Twilio's idiomatic names contain
// neither substring, so the basic correlator never sees the pair. Without
// this correlator, both halves get vaulted as independent bearer-style
// credentials and the proxy's basic-swap refuses because the two halves
// resolve to different *vault.Credential pointers (basic_decoder.go:102).
//
// Order: registered BEFORE basicCorrelator in correlate.go so a hypothetical
// future Twilio variable name that happens to contain "USER" doesn't get
// claimed by the generic basic pass first. (Today neither idiom contains
// USER, so the ordering is defensive, not load-bearing.)
type twilioCorrelator struct{}

// Detect emits one Group per valid TWILIO_ACCOUNT_SID candidate that has a
// decoration-matched TWILIO_AUTH_TOKEN partner. Consumed candidates (both
// halves of each pair) are removed from remaining.
func (twilioCorrelator) Detect(candidates []Candidate) (groups []Group, remaining []Candidate) {
	byKey := make(map[string]Candidate, len(candidates))
	for _, c := range candidates {
		byKey[c.Key] = c
	}
	consumed := make(map[string]struct{}, len(candidates))

	for _, c := range candidates {
		m := twilioAccountSIDRegex.FindStringSubmatch(c.Key)
		if m == nil {
			continue
		}
		if !twilioAccountSIDValue.MatchString(c.Value) {
			continue
		}
		prefix := m[1]

		tokenKey := prefix + "TWILIO_AUTH_TOKEN"
		token, ok := byKey[tokenKey]
		if !ok {
			continue
		}

		groups = append(groups, Group{
			Scheme:  "basic",
			Name:    token.Key, // password var's key, matching basicCorrelator
			Members: []Candidate{c, token},
			Basic: &BasicGroup{
				Username:    c.Value,
				Password:    token.Value,
				UsernameVar: c.Key,
				PasswordVar: token.Key,
			},
		})
		consumed[c.Key] = struct{}{}
		consumed[token.Key] = struct{}{}
	}

	for _, c := range candidates {
		if _, done := consumed[c.Key]; done {
			continue
		}
		remaining = append(remaining, c)
	}
	return groups, remaining
}
