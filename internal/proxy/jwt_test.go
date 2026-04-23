package proxy

import (
	"strings"
	"testing"
)

func TestBase64URL_RoundTrip(t *testing.T) {
	in := []byte{0xFF, 0x00, 0x10, 0x20, 0x7F}
	enc := base64URLEncode(in)
	if strings.ContainsAny(enc, "+/=") {
		t.Errorf("base64url should not contain +, /, or =: %q", enc)
	}
	out, err := base64URLDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Errorf("round-trip mismatch: %v vs %v", in, out)
	}
}

func TestDeterministicJSON_PreservesKeyOrder(t *testing.T) {
	in := []byte(`{"iss":123,"iat":1700000000,"exp":1700000600}`)
	got, err := reserializeDeterministic(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(in) {
		t.Errorf("reserialize reordered keys:\n got=%s\nwant=%s", got, in)
	}
}

func TestDeterministicJSON_PreservesNumericForm(t *testing.T) {
	// iss as an int must stay as an int, not stringified.
	in := []byte(`{"iss":42}`)
	got, err := reserializeDeterministic(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(in) {
		t.Errorf("numeric form lost: got %s", got)
	}
}
