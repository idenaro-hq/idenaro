package i18n

import (
	"io/fs"
	"strings"

	"idenaro/internal/finding"
)

// Translation holds localized description and recommendation for a single finding.
type Translation struct {
	Description    string
	Recommendation string
}

// LoadGerman returns German translations keyed by finding ID,
// parsed from the embedded *-de.md module documentation files.
func LoadGerman() map[string]Translation {
	out := make(map[string]Translation)
	entries, err := fs.ReadDir(DocFS, "docs/modules")
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, "-de.md") {
			continue
		}
		data, err := DocFS.ReadFile("docs/modules/" + name)
		if err != nil {
			continue
		}
		parseMarkdown(string(data), out)
	}
	return out
}

// ApplyToFindings returns a copy of findings with Description and Recommendation
// overridden wherever a matching translation exists.
func ApplyToFindings(findings []finding.Finding, tx map[string]Translation) []finding.Finding {
	if len(tx) == 0 {
		return findings
	}
	result := make([]finding.Finding, len(findings))
	copy(result, findings)
	for i := range result {
		if t, ok := tx[result[i].ID]; ok {
			if t.Description != "" {
				result[i].Description = t.Description
			}
			if t.Recommendation != "" {
				result[i].Recommendation = t.Recommendation
			}
		}
	}
	return result
}

// parseMarkdown parses one module markdown doc (sections split by "\n---\n")
// and adds entries to out keyed by finding ID.
func parseMarkdown(src string, out map[string]Translation) {
	for _, section := range strings.Split(src, "\n---\n") {
		section = strings.TrimSpace(section)
		if section == "" {
			continue
		}
		nl := strings.IndexByte(section, '\n')
		if nl < 0 {
			continue
		}
		header := strings.TrimPrefix(strings.TrimSpace(section[:nl]), "## ")
		body := strings.TrimSpace(section[nl+1:])

		parts := strings.SplitN(header, "|", 3)
		id := strings.TrimSpace(parts[0])
		if id == "" || strings.HasSuffix(id, "-overview") {
			continue
		}

		desc, rec := splitDescRec(body)
		out[id] = Translation{
			Description:    stripBackticks(desc),
			Recommendation: stripBackticks(rec),
		}
	}
}

func splitDescRec(body string) (desc, rec string) {
	idx := strings.Index(body, "\n### ")
	if idx < 0 {
		return strings.TrimSpace(body), ""
	}
	desc = strings.TrimSpace(body[:idx])
	rest := strings.TrimSpace(body[idx:])
	nl := strings.IndexByte(rest, '\n')
	if nl < 0 {
		return desc, ""
	}
	rec = joinBullets(strings.TrimSpace(rest[nl+1:]))
	return desc, rec
}

func joinBullets(s string) string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "- "):
			lines = append(lines, strings.TrimPrefix(l, "- "))
		case l != "" && !strings.HasPrefix(l, "#"):
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

func stripBackticks(s string) string {
	return strings.ReplaceAll(s, "`", "")
}
