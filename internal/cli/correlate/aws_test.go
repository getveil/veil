package correlate

import (
	"reflect"
	"sort"
	"testing"
)

// sortCandidates returns a copy sorted by Key for deterministic comparisons.
func sortCandidates(cs []Candidate) []Candidate {
	out := append([]Candidate(nil), cs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func TestAWSCorrelator(t *testing.T) {
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
			name: "lone access-key-ID stays bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
			},
		},
		{
			name: "canonical pair (no session)",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7REDACTD",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: nil,
		},
		{
			name: "canonical triple",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "ASIAIOSFODNN7REDACTD"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "ASIAIOSFODNN7REDACTD"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
					{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
				},
				AWS: &AWSGroup{
					AccessKeyID:     "ASIAIOSFODNN7REDACTD",
					SecretKey:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					SessionToken:    "FwoGZXIvYXdzEJr//////////wEaDP",
					AccessKeyIDVar:  "AWS_ACCESS_KEY_ID",
					SecretKeyVar:    "AWS_SECRET_ACCESS_KEY",
					SessionTokenVar: "AWS_SESSION_TOKEN",
				},
			}},
			wantRem: nil,
		},
		{
			name: "prefixed pair",
			input: []Candidate{
				{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
				{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "PROD_AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
					{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7REDACTD",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					AccessKeyIDVar: "PROD_AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "PROD_AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: nil,
		},
		{
			name: "suffixed pair",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAIOSFODNN7REDACTD"},
				{Key: "AWS_SECRET_ACCESS_KEY_OLD", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID_OLD",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAIOSFODNN7REDACTD"},
					{Key: "AWS_SECRET_ACCESS_KEY_OLD", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7REDACTD",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID_OLD",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY_OLD",
				},
			}},
			wantRem: nil,
		},
		{
			name: "two disjoint groups (PROD_ and DEV_)",
			input: []Candidate{
				{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAPRODREDACTD00001"},
				{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "prod/secret/example"},
				{Key: "DEV_AWS_ACCESS_KEY_ID", Value: "AKIADEVREDACTD000001"},
				{Key: "DEV_AWS_SECRET_ACCESS_KEY", Value: "dev/secret/example"},
			},
			wantGroups: []Group{
				{
					Scheme: "aws",
					Name:   "PROD_AWS_ACCESS_KEY_ID",
					Members: []Candidate{
						{Key: "PROD_AWS_ACCESS_KEY_ID", Value: "AKIAPRODREDACTD00001"},
						{Key: "PROD_AWS_SECRET_ACCESS_KEY", Value: "prod/secret/example"},
					},
					AWS: &AWSGroup{
						AccessKeyID:    "AKIAPRODREDACTD00001",
						SecretKey:      "prod/secret/example",
						AccessKeyIDVar: "PROD_AWS_ACCESS_KEY_ID",
						SecretKeyVar:   "PROD_AWS_SECRET_ACCESS_KEY",
					},
				},
				{
					Scheme: "aws",
					Name:   "DEV_AWS_ACCESS_KEY_ID",
					Members: []Candidate{
						{Key: "DEV_AWS_ACCESS_KEY_ID", Value: "AKIADEVREDACTD000001"},
						{Key: "DEV_AWS_SECRET_ACCESS_KEY", Value: "dev/secret/example"},
					},
					AWS: &AWSGroup{
						AccessKeyID:    "AKIADEVREDACTD000001",
						SecretKey:      "dev/secret/example",
						AccessKeyIDVar: "DEV_AWS_ACCESS_KEY_ID",
						SecretKeyVar:   "DEV_AWS_SECRET_ACCESS_KEY",
					},
				},
			},
			wantRem: nil,
		},
		{
			name: "canonical + orphan _OLD suffix stays bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAOLDROTATED000001"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7REDACTD",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
				},
			}},
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID_OLD", Value: "AKIAOLDROTATED000001"},
			},
		},
		{
			name: "invalid AKID shape — all three stay bearer",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "not_akia_value_12345"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "some_long_entropy_enough_sk"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "not_akia_value_12345"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "some_long_entropy_enough_sk"},
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
		},
		{
			name: "secret without ID stays bearer",
			input: []Candidate{
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
			},
		},
		{
			name: "session token without pair stays bearer",
			input: []Candidate{
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
			wantGroups: nil,
			wantRem: []Candidate{
				{Key: "AWS_SESSION_TOKEN", Value: "FwoGZXIvYXdzEJr//////////wEaDP"},
			},
		},
		{
			name: "non-AWS noise preserved alongside group",
			input: []Candidate{
				{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
				{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				{Key: "DATABASE_URL", Value: "postgres://u:p@h/db"},
				{Key: "OPENAI_API_KEY", Value: "sk-proj-1234567890abcdef"},
			},
			wantGroups: []Group{{
				Scheme: "aws",
				Name:   "AWS_ACCESS_KEY_ID",
				Members: []Candidate{
					{Key: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7REDACTD"},
					{Key: "AWS_SECRET_ACCESS_KEY", Value: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY"},
				},
				AWS: &AWSGroup{
					AccessKeyID:    "AKIAIOSFODNN7REDACTD",
					SecretKey:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYREDACTDKEYY",
					AccessKeyIDVar: "AWS_ACCESS_KEY_ID",
					SecretKeyVar:   "AWS_SECRET_ACCESS_KEY",
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
			var c awsCorrelator
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
