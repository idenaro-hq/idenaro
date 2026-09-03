package checks

import (
	"fmt"
	"strings"

	"idenaro/internal/finding"
)

// UserSearch analyses a response from a user-listing endpoint and returns
// findings if the endpoint appears to expose user data without authentication.
func UserSearch(host, endpointURL, apiName, bodyStr, contentType string, statusCode int, redirected bool) []finding.Finding {
	if statusCode != 200 || redirected {
		return nil
	}

	looksLikeUsers := strings.Contains(contentType, "json") &&
		(strings.Contains(bodyStr, `"email"`) ||
			strings.Contains(bodyStr, `"username"`) ||
			strings.Contains(bodyStr, `"userId"`) ||
			(strings.Contains(bodyStr, `"id"`) && strings.Contains(bodyStr, `"name"`)))

	if looksLikeUsers {
		f := finding.NewFinding(moduleName, host,
			fmt.Sprintf("User data accessible without authentication: %s", apiName),
			fmt.Sprintf("The %s at %s returned what appears to be user data (JSON with email/username/id fields) "+
				"without requiring authentication. This enables mass user enumeration.", apiName, endpointURL),
			finding.High,
		)
		f.ID = "enum-user-api"
		f.Evidence = []string{
			fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL),
			fmt.Sprintf("Content-Type: %s", contentType),
			fmt.Sprintf("Response preview: %s", truncate(bodyStr, 200)),
		}
		f.Confidence = "MEDIUM"
		f.Recommendation = "Require authentication for all user management and listing endpoints. " +
			"Apply principle of least privilege - regular users should not be able to enumerate all accounts."
		f.Tags = []string{"enumeration", "iam"}
		return []finding.Finding{f}
	}

	f := finding.NewFinding(moduleName, host,
		fmt.Sprintf("Identity endpoint accessible without authentication: %s", apiName),
		fmt.Sprintf("The %s at %s responded with HTTP 200 without authentication. "+
			"Manual review recommended to determine if user data is exposed.", apiName, endpointURL),
		finding.Medium,
	)
	f.Evidence = []string{fmt.Sprintf("HTTP %d at %s", statusCode, endpointURL)}
	f.Confidence = "LOW"
	f.Recommendation = "Verify this endpoint requires authentication and does not expose user data."
	f.Tags = []string{"enumeration", "iam"}
	return []finding.Finding{f}
}
