package placeholder

import "unicode"

// charClassFake generates a same-length replacement for value, preserving
// any leading alphanumeric prefix (up to a separator like '-' or '_'),
// preserving non-alphanumeric characters at their positions, and replacing
// each alphanumeric character with a random character of the same class
// (digit, lowercase, uppercase).
func charClassFake(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}

	// Detect a leading alphanumeric prefix ending at a common separator.
	prefixEnd := 0
	for i, r := range runes {
		if r == '-' || r == '_' {
			// Include the separator in the prefix.
			prefixEnd = i + 1
			break
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			// Non-alpha, non-separator: no prefix.
			break
		}
	}

	// Count characters that need random replacement (after prefix).
	var digitCount, lowerCount, upperCount int
	for _, r := range runes[prefixEnd:] {
		switch {
		case unicode.IsDigit(r):
			digitCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsUpper(r):
			upperCount++
		}
	}

	// Generate random characters in batches.
	const digits = "0123456789"
	const lowers = "abcdefghijklmnopqrstuvwxyz"
	const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randDigits := randFromAlphabet(digitCount, digits)
	randLowers := randFromAlphabet(lowerCount, lowers)
	randUppers := randFromAlphabet(upperCount, uppers)

	di, li, ui := 0, 0, 0
	result := make([]rune, len(runes))

	// Copy prefix verbatim.
	copy(result, runes[:prefixEnd])

	// Replace each character after the prefix.
	for i := prefixEnd; i < len(runes); i++ {
		r := runes[i]
		switch {
		case unicode.IsDigit(r):
			result[i] = rune(randDigits[di])
			di++
		case unicode.IsLower(r):
			result[i] = rune(randLowers[li])
			li++
		case unicode.IsUpper(r):
			result[i] = rune(randUppers[ui])
			ui++
		default:
			// Preserve separators and other non-alphanumeric characters.
			result[i] = r
		}
	}

	return string(result)
}
