package finding

import "fmt"

// Severity represents the risk level of a detected security issue.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// severityWeight maps each severity level to a numeric value used for sorting
// and comparison. Higher weight means higher severity.
var severityWeight = map[Severity]int{
	Critical: 5,
	High:     4,
	Medium:   3,
	Low:      2,
	Info:     1,
}

// SeverityOrder is exported so the engine and other packages can access
// severity weights without importing unexported symbols.
var SeverityOrder = severityWeight

// Finding represents a single detected security issue on a scanned host.
type Finding struct {
	ID             string   `json:"id"`
	Module         string   `json:"module"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	Confidence     string   `json:"confidence"` // "HIGH" | "MEDIUM" | "LOW"
	RiskScore      int      `json:"risk_score"`
	Host           string   `json:"host"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	NIS2Articles   []string `json:"nis2_articles,omitempty"`
	Tags           []string `json:"tags"`
}

// New constructs a Finding with a deterministic ID, default MEDIUM confidence,
// and the module name pre-populated as the first tag. Callers should set
// Evidence, Recommendation, Confidence, and additional Tags before returning.
func New(moduleName, hostName, title, description string, severity Severity) Finding {
	return Finding{
		ID:          fmt.Sprintf("%s-%s", moduleName, titleToID(title)),
		Module:      moduleName,
		Host:        hostName,
		Title:       title,
		Description: description,
		Severity:    severity,
		Confidence:  "MEDIUM",
		Evidence:    []string{},
		Tags:        []string{moduleName},
	}
}

// NewFinding is an alias kept for backwards compatibility with all existing
// module code that calls NewFinding. Prefer New in new code.
func NewFinding(moduleName, hostName, title, description string, severity Severity) Finding {
	return New(moduleName, hostName, title, description, severity)
}

// Weight returns the numeric severity weight for this finding, used when
// sorting findings from most to least severe.
func (f Finding) Weight() int {
	return severityWeight[f.Severity]
}

// titleToID converts a human-readable finding title into a URL-safe identifier
// by keeping only alphanumeric characters and replacing separators with hyphens.
func titleToID(title string) string {
	idBytes := make([]byte, 0, len(title))
	for i := 0; i < len(title); i++ {
		ch := title[i]
		switch {
		case ch == ' ' || ch == '/' || ch == '(' || ch == ')':
			idBytes = append(idBytes, '-')
		case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-':
			idBytes = append(idBytes, ch)
		}
	}
	return string(idBytes)
}
