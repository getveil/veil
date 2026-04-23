package correlate

import "regexp"

// awsKeyIDRegex captures decoration around the AWS_ACCESS_KEY_ID token.
// Case-sensitive, uppercase only — AWS SDKs do not honor lowercase env
// var names, so loosening case would invite false positives against
// user-owned lowercase keys like my_aws_access_key_id_override.
var awsKeyIDRegex = regexp.MustCompile(`^(.*?)AWS_ACCESS_KEY_ID(.*)$`)

// awsAccessKeyIDValue mirrors the add-time regex used by runAddAWS. Only
// real AKIA|ASIA-shaped values trigger correlation; local dev stubs and
// mock fixtures fall through to bearer.
var awsAccessKeyIDValue = regexp.MustCompile(`^(AKIA|ASIA)[A-Z0-9]{16}$`)

// awsCorrelator pairs an AWS access key ID with its secret (and optional
// session token) using strict decoration matching.
type awsCorrelator struct{}

// Detect emits one Group per valid access-key-ID candidate that has a
// decoration-matched secret partner. Optional session token is included
// when present under the same decoration. Consumed candidates (including
// the session token) are removed from remaining.
func (awsCorrelator) Detect(candidates []Candidate) (groups []Group, remaining []Candidate) {
	byKey := make(map[string]Candidate, len(candidates))
	for _, c := range candidates {
		byKey[c.Key] = c
	}
	consumed := make(map[string]struct{}, len(candidates))

	for _, c := range candidates {
		m := awsKeyIDRegex.FindStringSubmatch(c.Key)
		if m == nil {
			continue
		}
		if !awsAccessKeyIDValue.MatchString(c.Value) {
			continue
		}
		prefix, suffix := m[1], m[2]

		secretKeyName := prefix + "AWS_SECRET_ACCESS_KEY" + suffix
		secretKey, ok := byKey[secretKeyName]
		if !ok {
			continue
		}

		sessionTokenName := prefix + "AWS_SESSION_TOKEN" + suffix
		sessionToken, hasSession := byKey[sessionTokenName]

		members := []Candidate{c, secretKey}
		if hasSession {
			members = append(members, sessionToken)
		}

		aws := &AWSGroup{
			AccessKeyID:    c.Value,
			SecretKey:      secretKey.Value,
			AccessKeyIDVar: c.Key,
			SecretKeyVar:   secretKey.Key,
		}
		if hasSession {
			aws.SessionToken = sessionToken.Value
			aws.SessionTokenVar = sessionToken.Key
		}

		groups = append(groups, Group{
			Scheme:  "aws",
			Name:    c.Key,
			Members: members,
			AWS:     aws,
		})
		consumed[c.Key] = struct{}{}
		consumed[secretKey.Key] = struct{}{}
		if hasSession {
			consumed[sessionToken.Key] = struct{}{}
		}
	}

	for _, c := range candidates {
		if _, done := consumed[c.Key]; done {
			continue
		}
		remaining = append(remaining, c)
	}
	return groups, remaining
}
