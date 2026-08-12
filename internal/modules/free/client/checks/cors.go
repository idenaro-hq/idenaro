package checks

import (
	"fmt"

	"idenaro/internal/finding"
)

// CORSResult builds findings from an already-completed CORS probe.
// acao is the Access-Control-Allow-Origin value; acac is whether ACAC: true was present.
// attackerOrigin is the origin that was injected in the probe request.
func CORSResult(host, endpointURL, attackerOrigin, acao string, acac bool) []finding.Finding {
	if acao == "" {
		f := finding.NewFinding(moduleName, host,
			"No CORS policy on relying party endpoint",
			fmt.Sprintf("The endpoint %s returned no Access-Control-Allow-Origin header for "+
				"Origin: %s. Cross-origin requests are rejected by default.", endpointURL, attackerOrigin),
			finding.Info,
		)
		f.ID = "client-cors-absent"
		f.Evidence = []string{
			fmt.Sprintf("Sent: Origin: %s (OPTIONS + GET)", attackerOrigin),
			fmt.Sprintf("Received: no Access-Control-Allow-Origin header from %s", endpointURL),
		}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2CORSVal}
		f.Tags = []string{moduleName, "client-cors"}
		return []finding.Finding{f}
	}

	reflected := acao == attackerOrigin
	wildcard := acao == "*"
	if !reflected && !wildcard {
		f := finding.NewFinding(moduleName, host,
			"CORS policy present - origin allowlisted",
			fmt.Sprintf("The endpoint %s returns Access-Control-Allow-Origin: %s. "+
				"The injected attacker origin was not reflected.", endpointURL, acao),
			finding.Info,
		)
		f.ID = "client-cors-allowed"
		f.Evidence = []string{
			fmt.Sprintf("Sent: Origin: %s", attackerOrigin),
			fmt.Sprintf("Received: Access-Control-Allow-Origin: %s (not reflected)", acao),
		}
		f.Confidence = "HIGH"
		f.NIS2Articles = []string{NIS2CORSVal}
		f.Tags = []string{moduleName, "client-cors"}
		return []finding.Finding{f}
	}

	var findings []finding.Finding

	desc := fmt.Sprintf("The endpoint %s reflects the injected Origin %q in Access-Control-Allow-Origin.",
		endpointURL, attackerOrigin)
	if wildcard {
		desc = fmt.Sprintf("The endpoint %s returns Access-Control-Allow-Origin: * "+
			"allowing any origin to make cross-site requests.", endpointURL)
	}
	f := finding.NewFinding(moduleName, host,
		"CORS misconfiguration on relying party endpoint",
		desc,
		finding.High,
	)
	if wildcard {
		f.ID = "cors-wildcard"
	} else {
		f.ID = "cors-reflected"
	}
	f.Evidence = []string{
		fmt.Sprintf("Sent: Origin: %s", attackerOrigin),
		fmt.Sprintf("Received: Access-Control-Allow-Origin: %s", acao),
		fmt.Sprintf("Endpoint: %s", endpointURL),
	}
	f.Confidence = "HIGH"
	f.Recommendation = "Validate the Origin header against a strict server-side allowlist. " +
		"Never reflect arbitrary origins or use wildcards on endpoints that handle auth state."
	f.NIS2Articles = []string{NIS2CORSVal}
	f.Tags = []string{moduleName, "client-cors"}
	findings = append(findings, f)

	if acac {
		f2 := finding.NewFinding(moduleName, host,
			"CORS misconfiguration with credentials enabled",
			fmt.Sprintf("The endpoint %s returns Access-Control-Allow-Origin: %s together with "+
				"Access-Control-Allow-Credentials: true. Any page hosted at %s can make credentialed "+
				"cross-site requests and read the response, enabling direct session and token theft.",
				endpointURL, acao, attackerOrigin),
			finding.Critical,
		)
		f2.ID = "cors-reflected"
		f2.Evidence = []string{
			fmt.Sprintf("Sent: Origin: %s", attackerOrigin),
			fmt.Sprintf("Received: Access-Control-Allow-Origin: %s", acao),
			"Received: Access-Control-Allow-Credentials: true",
			fmt.Sprintf("Endpoint: %s", endpointURL),
		}
		f2.Confidence = "HIGH"
		f2.Recommendation = "Never combine Access-Control-Allow-Credentials: true with a reflected or " +
			"wildcard ACAO value. Use a strict origin allowlist and set ACAC only on explicitly trusted origins."
		f2.NIS2Articles = []string{NIS2CORSVal}
		f2.Tags = []string{moduleName, "client-cors"}
		findings = append(findings, f2)
	}

	return findings
}
