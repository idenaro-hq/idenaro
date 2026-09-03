package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// CallbackDebug checks the response body of a callback endpoint for stack traces
// or debug output that reveals implementation details.
func CallbackDebug(host, endpointURL, callbackName, bodyStr string) []finding.Finding {
	lower := strings.ToLower(bodyStr)
	for _, indicator := range debugIndicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			f := finding.NewFinding(moduleName, host,
				fmt.Sprintf("Debug information leaked on %s", callbackName),
				fmt.Sprintf("The %s at %s returned what appears to be a stack trace or debug output "+
					"when accessed without a valid auth context. This reveals implementation details "+
					"useful for targeted attacks.", callbackName, endpointURL),
				finding.Medium,
			)
			f.ID = "redirects-debug-leak"
			f.Evidence = []string{
				fmt.Sprintf("HTTP response at %s", endpointURL),
				fmt.Sprintf("Debug indicator found: %q", indicator),
			}
			f.Confidence = "MEDIUM"
			f.Recommendation = "Disable debug output in production. Return generic error pages for all error conditions."
			f.Tags = []string{"redirects", "iam"}
			return []finding.Finding{f}
		}
	}
	return nil
}
