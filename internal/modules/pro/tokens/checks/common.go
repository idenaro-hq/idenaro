package checks

const moduleName = "tokens"

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func shortenURL(u string) string {
	if len(u) > 80 {
		return "..." + u[len(u)-77:]
	}
	return u
}
