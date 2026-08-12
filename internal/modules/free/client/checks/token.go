package checks

import (
	"fmt"
	"net/http"

	"idenaro/internal/finding"
)

// AlgNone builds findings for the alg:none JWT probe given the baseline and probe response codes.
func AlgNone(host, endpointURL string, baseline, probeStatus int) []finding.Finding {
	if probeStatus == baseline {
		f := finding.NewFinding(moduleName, host,
			"alg:none probe inconclusive - response matches unauthenticated baseline",
			fmt.Sprintf("The endpoint %s returned HTTP %d with an alg:none JWT, identical to the "+
				"unauthenticated baseline (HTTP %d). The Authorization header appears to be ignored "+
				"(e.g. the endpoint uses cookie-based sessions or is a reverse-proxy auth subrequest). "+
				"JWT signature enforcement cannot be confirmed through probing alone.",
				endpointURL, probeStatus, baseline),
			finding.Info,
		)
		f.ID = "client-alg-none-inconclusive"
		f.Evidence = []string{
			fmt.Sprintf("Baseline: GET %s (no Authorization) → HTTP %d", endpointURL, baseline),
			"Probe:    Authorization: Bearer <alg:none JWT, exp=year 2286, empty signature>",
			fmt.Sprintf("Result:   HTTP %d (matches baseline - JWT may not be evaluated)", probeStatus),
		}
		f.Confidence = "LOW"
		f.NIS2Articles = []string{NIS2TokenVal}
		f.Tags = []string{moduleName, "client-token-validation"}
		return []finding.Finding{f}
	}

	if probeStatus == http.StatusUnauthorized {
		f := finding.NewFinding(moduleName, host,
			"Token signatures enforced - alg:none JWT rejected",
			fmt.Sprintf("The endpoint %s returned HTTP 401 for an alg:none JWT while the "+
				"unauthenticated baseline returned HTTP %d. The change in response confirms "+
				"the endpoint evaluated and rejected the unsigned token.", endpointURL, baseline),
			finding.Info,
		)
		f.ID = "client-alg-none-enforced"
		f.Evidence = []string{
			fmt.Sprintf("Baseline: GET %s (no Authorization) → HTTP %d", endpointURL, baseline),
			"Probe:    Authorization: Bearer <alg:none JWT, exp=year 2286, empty signature>",
			fmt.Sprintf("Result:   HTTP 401 from %s (differs from baseline)", endpointURL),
		}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2TokenVal}
		f.Tags = []string{moduleName, "client-token-validation"}
		return []finding.Finding{f}
	}

	sev := finding.High
	conf := "MEDIUM"
	if probeStatus == http.StatusOK {
		sev = finding.Critical
		conf = "HIGH"
	}

	f := finding.NewFinding(moduleName, host,
		"JWT alg:none accepted by relying party",
		fmt.Sprintf("The application accepted a JWT with alg:none (no signature) at %s. "+
			"An attacker can forge arbitrary identity claims without any key material.", endpointURL),
		sev,
	)
	f.ID = "oidc-alg-none"
	f.Evidence = []string{
		"Sent: Authorization: Bearer <header.payload.> - alg:none, empty signature, exp=year 2286",
		fmt.Sprintf("Received: HTTP %d from %s", probeStatus, endpointURL),
	}
	f.Confidence = conf
	f.Recommendation = "Reject any JWT whose alg header is \"none\". Enforce a server-side allowlist " +
		"of accepted signing algorithms (e.g. RS256 only) and never derive the algorithm from the token itself."
	f.NIS2Articles = []string{NIS2TokenVal}
	f.Tags = []string{moduleName, "client-token-validation"}
	return []finding.Finding{f}
}

// ExpiredToken builds findings for the expired-JWT probe given the baseline and probe response codes.
func ExpiredToken(host, endpointURL string, baseline, probeStatus int) []finding.Finding {
	if probeStatus == baseline {
		f := finding.NewFinding(moduleName, host,
			"Expired JWT probe inconclusive - response matches unauthenticated baseline",
			fmt.Sprintf("The endpoint %s returned HTTP %d with an expired JWT, identical to the "+
				"unauthenticated baseline (HTTP %d). The Authorization header appears to be ignored. "+
				"Token expiry enforcement cannot be confirmed through probing alone.",
				endpointURL, probeStatus, baseline),
			finding.Info,
		)
		f.ID = "client-expired-token-inconclusive"
		f.Evidence = []string{
			fmt.Sprintf("Baseline: GET %s (no Authorization) → HTTP %d", endpointURL, baseline),
			"Probe:    Authorization: Bearer <alg:none JWT, exp=946688400 (2000-01-01T01:00:00Z)>",
			fmt.Sprintf("Result:   HTTP %d (matches baseline - JWT may not be evaluated)", probeStatus),
		}
		f.Confidence = "LOW"
		f.NIS2Articles = []string{NIS2TokenVal}
		f.Tags = []string{moduleName, "client-token-validation"}
		return []finding.Finding{f}
	}

	if probeStatus == http.StatusUnauthorized {
		f := finding.NewFinding(moduleName, host,
			"Token expiry enforced - expired JWT rejected",
			fmt.Sprintf("The endpoint %s returned HTTP 401 for an expired JWT (exp=2000-01-01) "+
				"while the unauthenticated baseline returned HTTP %d. The change in response "+
				"confirms the endpoint evaluated and rejected the expired token.", endpointURL, baseline),
			finding.Info,
		)
		f.ID = "client-expired-token-enforced"
		f.Evidence = []string{
			fmt.Sprintf("Baseline: GET %s (no Authorization) → HTTP %d", endpointURL, baseline),
			"Probe:    Authorization: Bearer <alg:none JWT, exp=946688400 (2000-01-01T01:00:00Z)>",
			fmt.Sprintf("Result:   HTTP 401 from %s (differs from baseline)", endpointURL),
		}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2TokenVal}
		f.Tags = []string{moduleName, "client-token-validation"}
		return []finding.Finding{f}
	}

	sev := finding.High
	conf := "MEDIUM"
	if probeStatus == http.StatusOK {
		conf = "HIGH"
	}

	f := finding.NewFinding(moduleName, host,
		"Expired JWT accepted by relying party",
		fmt.Sprintf("The application accepted a JWT whose exp was set to 2000-01-01T01:00:00Z at %s. "+
			"Stolen tokens remain valid indefinitely when expiration is not enforced.", endpointURL),
		sev,
	)
	f.ID = "client-expired-token-accepted"
	f.Evidence = []string{
		"Sent: Authorization: Bearer <header.payload.> - alg:none, exp=946688400 (2000-01-01T01:00:00Z)",
		fmt.Sprintf("Received: HTTP %d from %s", probeStatus, endpointURL),
	}
	f.Confidence = conf
	f.Recommendation = "Validate the exp claim on every incoming token. Reject any token where exp is " +
		"in the past, regardless of other claims."
	f.NIS2Articles = []string{NIS2TokenVal}
	f.Tags = []string{moduleName, "client-token-validation"}
	return []finding.Finding{f}
}
