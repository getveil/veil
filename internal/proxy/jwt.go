package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// base64URLEncode returns the base64url-no-padding encoding (JWT form).
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// base64URLDecode decodes base64url with optional padding.
func base64URLDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// reserializeDeterministic takes a JSON object as bytes and returns it
// re-serialized with the original key order preserved. We parse into a
// map[string]json.RawMessage (so every value is captured as its original
// raw JSON bytes), then walk the input bytes with a tiny state machine
// to extract the top-level key order. The output is re-emitted in that
// order with no whitespace between tokens.
//
// Used for JWT header/payload re-signing where the byte-exact input
// (modulo whitespace) must survive a round-trip so signatures verify.
func reserializeDeterministic(raw []byte) ([]byte, error) {
	var byKey map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byKey); err != nil {
		return nil, err
	}
	order, err := extractTopLevelKeyOrder(raw)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteByte('{')
	for i, k := range order {
		if i > 0 {
			out.WriteByte(',')
		}
		kb, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		out.Write(kb)
		out.WriteByte(':')
		val, ok := byKey[k]
		if !ok {
			return nil, fmt.Errorf("key %q present in order but missing from map", k)
		}
		// Trim whitespace around the value to produce a compact re-emission.
		out.Write(bytes.TrimSpace(val))
	}
	out.WriteByte('}')
	return out.Bytes(), nil
}

// extractTopLevelKeyOrder scans a JSON object's bytes and returns the
// top-level keys in their original order. It tracks string escape state,
// brace depth, and bracket depth to skip over nested values correctly.
func extractTopLevelKeyOrder(raw []byte) ([]string, error) {
	var keys []string
	i := 0
	n := len(raw)
	// Skip leading whitespace.
	for i < n && isJSONWhitespace(raw[i]) {
		i++
	}
	if i >= n || raw[i] != '{' {
		return nil, fmt.Errorf("expected '{' at start of object")
	}
	i++ // consume '{'
	for i < n {
		// Skip whitespace / commas.
		for i < n && (isJSONWhitespace(raw[i]) || raw[i] == ',') {
			i++
		}
		if i >= n {
			break
		}
		if raw[i] == '}' {
			return keys, nil
		}
		if raw[i] != '"' {
			return nil, fmt.Errorf("expected '\"' at pos %d, got %q", i, raw[i])
		}
		// Read key string.
		key, end, err := readJSONString(raw, i)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
		i = end
		// Skip whitespace to ':'.
		for i < n && isJSONWhitespace(raw[i]) {
			i++
		}
		if i >= n || raw[i] != ':' {
			return nil, fmt.Errorf("expected ':' after key")
		}
		i++
		// Skip whitespace before value.
		for i < n && isJSONWhitespace(raw[i]) {
			i++
		}
		// Skip over the value.
		i, err = skipJSONValue(raw, i)
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("unterminated object")
}

func isJSONWhitespace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r'
}

// readJSONString reads a JSON string starting at raw[start] (which must be
// '"') and returns the decoded string and the index just past the closing
// '"'.
func readJSONString(raw []byte, start int) (string, int, error) {
	if start >= len(raw) || raw[start] != '"' {
		return "", 0, fmt.Errorf("not at a string")
	}
	i := start + 1
	for i < len(raw) {
		c := raw[i]
		if c == '\\' {
			i += 2
			continue
		}
		if c == '"' {
			// Include the quotes in the slice passed to json.Unmarshal.
			var s string
			if err := json.Unmarshal(raw[start:i+1], &s); err != nil {
				return "", 0, err
			}
			return s, i + 1, nil
		}
		i++
	}
	return "", 0, fmt.Errorf("unterminated string")
}

// skipJSONValue advances past a single JSON value starting at raw[start]
// and returns the index just past it.
func skipJSONValue(raw []byte, start int) (int, error) {
	i := start
	n := len(raw)
	if i >= n {
		return 0, fmt.Errorf("empty value")
	}
	switch raw[i] {
	case '"':
		_, end, err := readJSONString(raw, i)
		return end, err
	case '{', '[':
		return skipJSONContainer(raw, i)
	default:
		// number, true, false, null — read until a structural char.
		for i < n {
			c := raw[i]
			if c == ',' || c == '}' || c == ']' || isJSONWhitespace(c) {
				return i, nil
			}
			i++
		}
		return i, nil
	}
}

// skipJSONContainer skips over a {...} or [...] value, honoring nested
// objects/arrays and string literals (which may themselves contain braces
// or brackets).
func skipJSONContainer(raw []byte, start int) (int, error) {
	depth := 0
	i := start
	n := len(raw)
	for i < n {
		c := raw[i]
		switch c {
		case '"':
			_, end, err := readJSONString(raw, i)
			if err != nil {
				return 0, err
			}
			i = end
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
		}
		i++
	}
	return 0, fmt.Errorf("unterminated container")
}
