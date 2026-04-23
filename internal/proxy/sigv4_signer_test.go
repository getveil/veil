package proxy

import "testing"

func TestCanonicalURI(t *testing.T) {
	cases := []struct {
		name, in, want string
		isS3           bool
	}{
		{"root path", "/", "/", false},
		{"normal path", "/foo/bar", "/foo/bar", false},
		{"percent-encoded reserved", "/a b", "/a%20b", false},
		{"s3 preserves double slash", "/foo//bar", "/foo//bar", true},
		{"non-s3 collapses double slash", "/foo//bar", "/foo/bar", false},
		{"dot segments collapsed non-s3", "/foo/./bar/..", "/foo/", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalURI(tc.in, tc.isS3)
			if got != tc.want {
				t.Errorf("canonicalURI(%q, s3=%v) = %q, want %q", tc.in, tc.isS3, got, tc.want)
			}
		})
	}
}

func TestCanonicalQueryString(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"single", "foo=bar", "foo=bar"},
		{"sort by name", "b=2&a=1", "a=1&b=2"},
		{"same name sort by value", "a=2&a=1", "a=1&a=2"},
		{"empty value keeps =", "a=", "a="},
		{"encode space", "a=1 2", "a=1%202"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalQueryString(tc.in)
			if got != tc.want {
				t.Errorf("canonicalQueryString(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalHeaders(t *testing.T) {
	hdr := map[string][]string{
		"Host":         {"s3.amazonaws.com"},
		"X-Amz-Date":   {"20150830T123600Z"},
		"Content-Type": {"  application/json   "},
	}
	signed := []string{"host", "x-amz-date", "content-type"}
	got := canonicalHeaders(hdr, signed)
	want := "host:s3.amazonaws.com\nx-amz-date:20150830T123600Z\ncontent-type:application/json\n"
	if got != want {
		t.Errorf("canonicalHeaders mismatch:\n got=%q\nwant=%q", got, want)
	}
}
