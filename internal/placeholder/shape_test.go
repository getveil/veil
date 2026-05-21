package placeholder

import (
	"strings"
	"testing"
)

func TestPassesValueShapeGate(t *testing.T) {
	cases := []struct {
		label string
		value string
		want  bool
	}{
		// CR regression cases — too short.
		{"slack_channel_general", "general", false},
		{"vercel_env_production", "production", false},
		{"vercel_region_iad1", "iad1", false},
		{"vercel_url_my_app", "my-app.vercel.app", false},
		// Boundary on length: 19 chars varied — fails.
		{"len_19_distinct_19", "abcdefghijklmnopqrs", false},
		// Boundary on length: 20 chars varied — passes.
		{"len_20_distinct_20", "abcdefghijklmnopqrst", true},
		// Length passes, distinct fails (5 distinct).
		{"distinct_5_fails", "abcdeabcdeabcdeabcde", false},
		// Length passes, distinct exactly 6 — passes.
		{"distinct_6_passes", "abcdefabcdefabcdefab", true},
		// All-same character — fails distinct.
		{"all_a_20", strings.Repeat("a", 20), false},
		{"all_a_100", strings.Repeat("a", 100), false},
		// Realistic long token.
		{"realistic_token", "sk-proj-AbCdEf01234567890123456789012345", true},
		// Empty.
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			got := passesValueShapeGate(tc.value)
			if got != tc.want {
				t.Errorf("passesValueShapeGate(%q) = %v, want %v (len=%d, distinct=%d)",
					tc.value, got, tc.want, len(tc.value), distinctBytes(tc.value))
			}
		})
	}
}
