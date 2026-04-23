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
