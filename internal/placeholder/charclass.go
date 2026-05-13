package placeholder

import "unicode"

// charClassFake returns a same-length replacement for value: every
// alphanumeric character is replaced with a random one of the same class
// (digit, lower, upper); non-alphanumeric characters (separators) are
// preserved at their positions. No byte of value is copied into the output —
// callers overlay a fixed-offset sentinel onto the result, and a preserved
// input byte past the sentinel would leak the secret (see C1, where copying
// the leading alphanumeric run before the first '-'/'_' separator left
// bytes 4..separator-1 of every charclass-fallback placeholder equal to the
// real secret).
func charClassFake(value string) string {
	runes := []rune(value)
	if len(runes) == 0 {
		return ""
	}

	var digitCount, lowerCount, upperCount int
	for _, r := range runes {
		switch {
		case unicode.IsDigit(r):
			digitCount++
		case unicode.IsLower(r):
			lowerCount++
		case unicode.IsUpper(r):
			upperCount++
		}
	}

	const digits = "0123456789"
	const lowers = "abcdefghijklmnopqrstuvwxyz"
	const uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

	randDigits := randFromAlphabet(digitCount, digits)
	randLowers := randFromAlphabet(lowerCount, lowers)
	randUppers := randFromAlphabet(upperCount, uppers)

	di, li, ui := 0, 0, 0
	result := make([]rune, len(runes))
	for i, r := range runes {
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
			result[i] = r
		}
	}

	return string(result)
}
