package checks

import "strings"

const moduleName = "csp"

func getEffective(d map[string][]string, directive, fallback string) []string {
	if v, ok := d[directive]; ok {
		return v
	}
	return d[fallback]
}

func containsAny(vals []string, targets ...string) bool {
	for _, v := range vals {
		vl := strings.ToLower(v)
		for _, t := range targets {
			if vl == strings.ToLower(t) {
				return true
			}
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
