package correlate

import (
	"sort"
	"testing"
)

func TestBasicCorrelator_HappyPath_USERNAME_PASSWORD(t *testing.T) {
	cands := []Candidate{
		{Key: "DB_USERNAME", Value: "alice"},
		{Key: "DB_PASSWORD", Value: "longsecret1234"}, // len=14, distinct=13
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	g := groups[0]
	if g.Scheme != "basic" {
		t.Errorf("scheme = %q, want basic", g.Scheme)
	}
	if g.Name != "DB_PASSWORD" {
		t.Errorf("name = %q, want DB_PASSWORD", g.Name)
	}
	if g.Basic.Username != "alice" || g.Basic.Password != "longsecret1234" {
		t.Errorf("group values mismatch: %+v", g.Basic)
	}
	if g.Basic.UsernameVar != "DB_USERNAME" || g.Basic.PasswordVar != "DB_PASSWORD" {
		t.Errorf("group var names mismatch: %+v", g.Basic)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %v, want empty", remaining)
	}
}

func TestBasicCorrelator_CrossPairs(t *testing.T) {
	tests := []struct {
		name     string
		userKey  string
		passKey  string
	}{
		{"USER+PASS", "DB_USER", "DB_PASS"},
		{"USER+PASSWORD", "DB_USER", "DB_PASSWORD"},
		{"USERNAME+PASS", "DB_USERNAME", "DB_PASS"},
		{"USERNAME+PASSWORD", "DB_USERNAME", "DB_PASSWORD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cands := []Candidate{
				{Key: tt.userKey, Value: "alice"},
				{Key: tt.passKey, Value: "longsecret1234"},
			}
			groups, _ := basicCorrelator{}.Detect(cands)
			if len(groups) != 1 {
				t.Fatalf("got %d groups, want 1", len(groups))
			}
			if groups[0].Basic.UsernameVar != tt.userKey {
				t.Errorf("UsernameVar = %q, want %q", groups[0].Basic.UsernameVar, tt.userKey)
			}
			if groups[0].Basic.PasswordVar != tt.passKey {
				t.Errorf("PasswordVar = %q, want %q", groups[0].Basic.PasswordVar, tt.passKey)
			}
		})
	}
}

func TestBasicCorrelator_PrefersLongerPasswordPartner(t *testing.T) {
	// When both DB_PASS and DB_PASSWORD are present alongside DB_USER, the
	// correlator prefers DB_PASSWORD (canonical name) over DB_PASS.
	cands := []Candidate{
		{Key: "DB_USER", Value: "alice"},
		{Key: "DB_PASS", Value: "longsecret1234"},
		{Key: "DB_PASSWORD", Value: "longersecret5678"},
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Basic.PasswordVar != "DB_PASSWORD" {
		t.Errorf("PasswordVar = %q, want DB_PASSWORD", groups[0].Basic.PasswordVar)
	}
	if len(remaining) != 1 || remaining[0].Key != "DB_PASS" {
		t.Errorf("remaining = %v, want [DB_PASS]", remaining)
	}
}

func TestBasicCorrelator_RefusesTrivialPassword(t *testing.T) {
	cands := []Candidate{
		{Key: "DB_USER", Value: "alice"},
		{Key: "DB_PASSWORD", Value: "test"}, // len=4, fails shape floor
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0", len(groups))
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining = %d, want 2 (both vars unconsumed)", len(remaining))
	}
}

func TestBasicCorrelator_RefusesEmptyUsername(t *testing.T) {
	cands := []Candidate{
		{Key: "DB_USERNAME", Value: ""},
		{Key: "DB_PASSWORD", Value: "longsecret1234"},
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0", len(groups))
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining = %d, want 2", len(remaining))
	}
}

func TestBasicCorrelator_NoPartnerLeavesUnconsumed(t *testing.T) {
	cands := []Candidate{
		{Key: "DB_USERNAME", Value: "alice"},
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0", len(groups))
	}
	if len(remaining) != 1 {
		t.Fatalf("remaining = %d, want 1", len(remaining))
	}
}

func TestBasicCorrelator_DecoratedPrefixAndSuffix(t *testing.T) {
	// FOO_USER_DEV + FOO_PASS_DEV — decoration on both sides.
	cands := []Candidate{
		{Key: "FOO_USER_DEV", Value: "alice"},
		{Key: "FOO_PASS_DEV", Value: "longsecret1234"},
	}
	groups, _ := basicCorrelator{}.Detect(cands)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Basic.PasswordVar != "FOO_PASS_DEV" {
		t.Errorf("PasswordVar = %q", groups[0].Basic.PasswordVar)
	}
}

func TestBasicCorrelator_DoesNotConsumeAWSTriple(t *testing.T) {
	// Regression: AWS vars don't contain USER/PASS substrings, so the basic
	// correlator must ignore them entirely.
	cands := []Candidate{
		{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 0 {
		t.Fatalf("got %d groups, want 0", len(groups))
	}
	// Sort by key for stable assertion.
	sort.Slice(remaining, func(i, j int) bool { return remaining[i].Key < remaining[j].Key })
	if len(remaining) != 2 || remaining[0].Key != "AWS_ACCESS_KEY_ID" || remaining[1].Key != "AWS_SECRET_ACCESS_KEY" {
		t.Errorf("remaining = %v, want both AWS vars", remaining)
	}
}

func TestBasicCorrelator_FirstUserWinsWhenMultiple(t *testing.T) {
	// Two USERNAME-like vars share a partner. The first one in input order
	// pairs; the second falls into remaining.
	cands := []Candidate{
		{Key: "DB_USERNAME", Value: "alice"},
		{Key: "DB_USER", Value: "admin"},
		{Key: "DB_PASSWORD", Value: "longsecret1234"},
	}
	groups, remaining := basicCorrelator{}.Detect(cands)
	if len(groups) != 1 {
		t.Fatalf("got %d groups, want 1", len(groups))
	}
	if groups[0].Basic.UsernameVar != "DB_USERNAME" {
		t.Errorf("UsernameVar = %q, want DB_USERNAME (first in input order)", groups[0].Basic.UsernameVar)
	}
	if len(remaining) != 1 || remaining[0].Key != "DB_USER" {
		t.Errorf("remaining = %v, want [DB_USER]", remaining)
	}
}

func TestHasBasicPasswordShape(t *testing.T) {
	cases := []struct {
		v    string
		want bool
	}{
		{"", false},
		{"short", false},
		{"123456789012", true},   // len=12, distinct=10
		{"12345678901", false},   // len=11
		{"aaaaaaaaaaaa", false},  // distinct=1
		{"aabbccdd1111", false},  // len=12, distinct=5 — fails distinct floor
		{"aabbccdd1122", true},   // len=12, distinct=6 — meets distinct floor exactly
		{"aabbccddeexx", true},   // len=12, distinct=6 (a,b,c,d,e,x)
		{"aabbccddeexy", true},   // len=12, distinct=7
	}
	for _, tc := range cases {
		if got := hasBasicPasswordShape(tc.v); got != tc.want {
			t.Errorf("hasBasicPasswordShape(%q) = %v, want %v", tc.v, got, tc.want)
		}
	}
}
