package report

import "strings"

// enc converts a UTF-8 string to Windows-1252 encoding required by fpdf's
// built-in fonts. German Umlauts, en/em dashes, and typographic quotes
// all fall within the Windows-1252 code page.
func enc(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			b.WriteByte(byte(r))
		case r == 'ä':
			b.WriteByte(0xe4)
		case r == 'ö':
			b.WriteByte(0xf6)
		case r == 'ü':
			b.WriteByte(0xfc)
		case r == 'Ä':
			b.WriteByte(0xc4)
		case r == 'Ö':
			b.WriteByte(0xd6)
		case r == 'Ü':
			b.WriteByte(0xdc)
		case r == 'ß':
			b.WriteByte(0xdf)
		case r == '-':
			b.WriteByte(0x96) // en dash
		case r == '-':
			b.WriteByte(0x97) // em dash
		case r == '‘': // left single quote
			b.WriteByte(0x91)
		case r == '’': // right single quote
			b.WriteByte(0x92)
		case r == '“': // left double quote
			b.WriteByte(0x93)
		case r == '”': // right double quote
			b.WriteByte(0x94)
		case r == '•':
			b.WriteByte(0x95)
		case r == '…':
			b.WriteByte(0x85)
		case r >= 0xa0 && r <= 0xff:
			b.WriteByte(byte(r))
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func trunc(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-3]) + "..."
}

func sevRGB(sev string) [3]int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return [3]int{220, 38, 38}
	case "HIGH":
		return [3]int{234, 88, 12}
	case "MEDIUM":
		return [3]int{217, 119, 6}
	case "LOW":
		return [3]int{101, 163, 13}
	case "INFO":
		return [3]int{2, 132, 199}
	default:
		return [3]int{100, 116, 139}
	}
}

func critColor(n int) [3]int {
	if n > 0 {
		return [3]int{220, 38, 38}
	}
	return [3]int{100, 116, 139}
}

func highColor(n int) [3]int {
	if n > 0 {
		return [3]int{234, 88, 12}
	}
	return [3]int{100, 116, 139}
}

func medColor(n int) [3]int {
	if n > 0 {
		return [3]int{217, 119, 6}
	}
	return [3]int{100, 116, 139}
}

func issueSeverityColor(violations []hostedFinding) [3]int {
	if len(violations) == 0 {
		return [3]int{100, 116, 139}
	}
	for _, v := range violations {
		if strings.ToUpper(v.F.Severity) == "CRITICAL" {
			return [3]int{220, 38, 38}
		}
	}
	for _, v := range violations {
		if strings.ToUpper(v.F.Severity) == "HIGH" {
			return [3]int{234, 88, 12}
		}
	}
	return [3]int{217, 119, 6}
}
