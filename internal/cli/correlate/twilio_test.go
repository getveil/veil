package correlate

import (
	"reflect"
	"strings"
	"testing"
)

// realTwilioSID is a syntactically valid Twilio Account SID: "AC" + 32 hex
// chars. The basicCorrelator can never see this pair because neither key
// contains USER/PASS substrings; the twilioCorrelator is the only correlator
// that can promote SID/TOKEN env-var pairs to a Basic group.
const (
	realTwilioSID   = "AC" + "0123456789abcdef0123456789abcdef"
	realTwilioToken = "fedcba9876543210fedcba9876543210"
)

func TestTwilioCorrelator(t *testing.T) {
	tests := []struct {
		name       string
		input      []Candidate
		wantGroups []Group
		wantRem    []Candidate
	}{
		{
			name:       "empty input",
			input:      nil,
			wantGroups: nil,
			wantRem:    nil,
		},
		{
			name: "canonical TWILIO_ pair",
			input: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
			wantGroups: []Group{{
				Scheme: "basic",
				Name:   "TWILIO_AUTH_TOKEN",
				Members: []Candidate{
					{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
					{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
				},
				Basic: &BasicGroup{
					Username:    realTwilioSID,
					Password:    realTwilioToken,
					UsernameVar: "TWILIO_ACCOUNT_SID",
					PasswordVar: "TWILIO_AUTH_TOKEN",
				},
			}},
			wantRem: nil,
		},
		{
			name: "lone SID stays uncorrelated",
			input: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
			},
		},
		{
			name: "lone TOKEN stays uncorrelated",
			input: []Candidate{
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
		},
		{
			name: "prefixed pair (PROD_TWILIO_*)",
			input: []Candidate{
				{Key: "PROD_TWILIO_ACCOUNT_SID", Value: realTwilioSID},
				{Key: "PROD_TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
			wantGroups: []Group{{
				Scheme: "basic",
				Name:   "PROD_TWILIO_AUTH_TOKEN",
				Members: []Candidate{
					{Key: "PROD_TWILIO_ACCOUNT_SID", Value: realTwilioSID},
					{Key: "PROD_TWILIO_AUTH_TOKEN", Value: realTwilioToken},
				},
				Basic: &BasicGroup{
					Username:    realTwilioSID,
					Password:    realTwilioToken,
					UsernameVar: "PROD_TWILIO_ACCOUNT_SID",
					PasswordVar: "PROD_TWILIO_AUTH_TOKEN",
				},
			}},
			wantRem: nil,
		},
		{
			name: "two disjoint pairs (PROD_TWILIO_ and DEV_TWILIO_)",
			input: []Candidate{
				{Key: "PROD_TWILIO_ACCOUNT_SID", Value: "AC" + strings.Repeat("a", 32)},
				{Key: "PROD_TWILIO_AUTH_TOKEN", Value: strings.Repeat("b", 32)},
				{Key: "DEV_TWILIO_ACCOUNT_SID", Value: "AC" + strings.Repeat("c", 32)},
				{Key: "DEV_TWILIO_AUTH_TOKEN", Value: strings.Repeat("d", 32)},
			},
			wantGroups: []Group{
				{
					Scheme: "basic",
					Name:   "PROD_TWILIO_AUTH_TOKEN",
					Members: []Candidate{
						{Key: "PROD_TWILIO_ACCOUNT_SID", Value: "AC" + strings.Repeat("a", 32)},
						{Key: "PROD_TWILIO_AUTH_TOKEN", Value: strings.Repeat("b", 32)},
					},
					Basic: &BasicGroup{
						Username:    "AC" + strings.Repeat("a", 32),
						Password:    strings.Repeat("b", 32),
						UsernameVar: "PROD_TWILIO_ACCOUNT_SID",
						PasswordVar: "PROD_TWILIO_AUTH_TOKEN",
					},
				},
				{
					Scheme: "basic",
					Name:   "DEV_TWILIO_AUTH_TOKEN",
					Members: []Candidate{
						{Key: "DEV_TWILIO_ACCOUNT_SID", Value: "AC" + strings.Repeat("c", 32)},
						{Key: "DEV_TWILIO_AUTH_TOKEN", Value: strings.Repeat("d", 32)},
					},
					Basic: &BasicGroup{
						Username:    "AC" + strings.Repeat("c", 32),
						Password:    strings.Repeat("d", 32),
						UsernameVar: "DEV_TWILIO_ACCOUNT_SID",
						PasswordVar: "DEV_TWILIO_AUTH_TOKEN",
					},
				},
			},
			wantRem: nil,
		},
		{
			name: "invalid SID shape — both stay uncorrelated",
			input: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: "not_an_account_sid"},
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: "not_an_account_sid"},
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
		},
		{
			name: "prefix mismatch (PROD_TWILIO_ACCOUNT_SID + DEV_TWILIO_AUTH_TOKEN) — no pair",
			input: []Candidate{
				{Key: "PROD_TWILIO_ACCOUNT_SID", Value: realTwilioSID},
				{Key: "DEV_TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "PROD_TWILIO_ACCOUNT_SID", Value: realTwilioSID},
				{Key: "DEV_TWILIO_AUTH_TOKEN", Value: realTwilioToken},
			},
		},
		{
			name: "non-Twilio noise preserved alongside group",
			input: []Candidate{
				{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
				{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
				{Key: "DATABASE_URL", Value: "postgres://u:p@h/db"},
				{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
			},
			wantGroups: []Group{{
				Scheme: "basic",
				Name:   "TWILIO_AUTH_TOKEN",
				Members: []Candidate{
					{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
					{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
				},
				Basic: &BasicGroup{
					Username:    realTwilioSID,
					Password:    realTwilioToken,
					UsernameVar: "TWILIO_ACCOUNT_SID",
					PasswordVar: "TWILIO_AUTH_TOKEN",
				},
			}},
			wantRem: []Candidate{
				{Key: "DATABASE_URL", Value: "postgres://u:p@h/db"},
				{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c twilioCorrelator
			gotGroups, gotRem := c.Detect(tt.input)

			if !reflect.DeepEqual(gotGroups, tt.wantGroups) {
				t.Errorf("groups mismatch:\n got = %#v\nwant = %#v", gotGroups, tt.wantGroups)
			}
			if !reflect.DeepEqual(sortCandidates(gotRem), sortCandidates(tt.wantRem)) {
				t.Errorf("remaining mismatch:\n got = %#v\nwant = %#v", gotRem, tt.wantRem)
			}
		})
	}
}

// TestTwilioCorrelator_DoesNotConsumeAWSTriple is the cross-correlator
// regression mirror of TestBasicCorrelator_DoesNotConsumeAWSTriple. AWS env
// vars don't contain ACCOUNT_SID/AUTH_TOKEN substrings, so the Twilio
// correlator must ignore them entirely.
func TestTwilioCorrelator_DoesNotConsumeAWSTriple(t *testing.T) {
	cands := []Candidate{
		{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
		{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
	}
	groups, remaining := twilioCorrelator{}.Detect(cands)
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0", len(groups))
	}
	if !reflect.DeepEqual(sortCandidates(remaining), sortCandidates(cands)) {
		t.Errorf("remaining mismatch:\n got = %#v\nwant = %#v", remaining, cands)
	}
}

// TestDetectAll_TwilioPairBecomesBasicGroup verifies the end-to-end
// dispatch path: a Twilio SID/TOKEN pair coming through DetectAll emerges
// as a basic-scheme Group, so init_phases.go's case "basic" branch vaults
// it as a paired credential.
func TestDetectAll_TwilioPairBecomesBasicGroup(t *testing.T) {
	in := []Candidate{
		{Key: "TWILIO_ACCOUNT_SID", Value: realTwilioSID},
		{Key: "TWILIO_AUTH_TOKEN", Value: realTwilioToken},
		{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
	}
	groups, remaining := DetectAll(in)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	g := groups[0]
	if g.Scheme != "basic" {
		t.Errorf("scheme = %q, want basic", g.Scheme)
	}
	if g.Basic == nil {
		t.Fatal("Basic is nil")
	}
	if g.Basic.UsernameVar != "TWILIO_ACCOUNT_SID" {
		t.Errorf("UsernameVar = %q, want TWILIO_ACCOUNT_SID", g.Basic.UsernameVar)
	}
	if g.Basic.PasswordVar != "TWILIO_AUTH_TOKEN" {
		t.Errorf("PasswordVar = %q, want TWILIO_AUTH_TOKEN", g.Basic.PasswordVar)
	}
	if g.Basic.Username != realTwilioSID {
		t.Errorf("Username = %q, want %q", g.Basic.Username, realTwilioSID)
	}
	if g.Basic.Password != realTwilioToken {
		t.Errorf("Password = %q, want %q", g.Basic.Password, realTwilioToken)
	}
	if len(remaining) != 1 || remaining[0].Key != "OPENAI_API_KEY" {
		t.Errorf("remaining = %v, want [OPENAI_API_KEY]", remaining)
	}
}
