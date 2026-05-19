package correlate

import (
	"reflect"
	"testing"
)

func TestDetectAll_EmptyInput(t *testing.T) {
	groups, remaining := DetectAll(nil)
	if len(groups) != 0 {
		t.Errorf("groups = %v, want empty", groups)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %v, want empty", remaining)
	}
}

func TestDetectAll_NoCorrelationJustPassesThrough(t *testing.T) {
	in := []Candidate{
		{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
		{Key: "DATABASE_URL", Value: "postgres://user:pw@h/db"},
	}
	groups, remaining := DetectAll(in)
	if len(groups) != 0 {
		t.Errorf("groups = %v, want empty", groups)
	}
	if !reflect.DeepEqual(remaining, in) {
		t.Errorf("remaining = %v, want %v", remaining, in)
	}
}

func TestDetectAll_AWSTripleIsConsumed(t *testing.T) {
	in := []Candidate{
		{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
		{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
		{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
	}
	groups, remaining := DetectAll(in)
	if len(groups) != 1 || groups[0].Scheme != "aws" {
		t.Fatalf("expected 1 aws group, got %v", groups)
	}
	if len(remaining) != 1 || remaining[0].Key != "OPENAI_API_KEY" {
		t.Errorf("remaining = %v, want only OPENAI_API_KEY", remaining)
	}
}

func TestDetectAll_BasicGroupFromMixedInput(t *testing.T) {
	cands := []Candidate{
		{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
		{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
		{Key: "GH_USERNAME", Value: "alice"},
		{Key: "GH_PASSWORD", Value: "ghp_realtoken1234"},
		{Key: "STRIPE_API_KEY", Value: "sk_test_aBcDeFgHiJkLmNoP"},
	}
	groups, remaining := DetectAll(cands)

	gotSchemes := make([]string, 0, len(groups))
	for _, g := range groups {
		gotSchemes = append(gotSchemes, g.Scheme)
	}
	wantHas := func(s string) bool {
		for _, x := range gotSchemes {
			if x == s {
				return true
			}
		}
		return false
	}
	if !wantHas("aws") {
		t.Errorf("missing aws group; got schemes=%v", gotSchemes)
	}
	if !wantHas("basic") {
		t.Errorf("missing basic group; got schemes=%v", gotSchemes)
	}

	// Only STRIPE_API_KEY should remain (uncorrelated bearer).
	if len(remaining) != 1 || remaining[0].Key != "STRIPE_API_KEY" {
		t.Errorf("remaining = %v, want [STRIPE_API_KEY]", remaining)
	}
}
