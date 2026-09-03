package report

// pdfStrings holds all localizable text used by the PDF generator.
type pdfStrings struct {
	// header / footer
	HeaderTitle     string
	HeaderConf      string
	FooterDirective string
	FooterPage      string // printf format, single %d for page number

	// compliance status labels
	StatusNonCompliant      string
	StatusRequiresAttention string
	StatusLargelyCompliant  string
	StatusCompliant         string
	StatusNotAssessed       string

	// cover page
	CoverPlatform     string
	CoverReportSub    string
	CoverDirective    string
	CoverMetaDate     string
	CoverMetaScanner  string
	CoverMetaScannerV string
	CoverMetaType     string
	CoverMetaTypeV    string
	CoverMetaMethod   string
	CoverMetaMethodV  string
	CoverMetaScope    string
	CoverMetaScopeV   string // printf with %d
	CoverMetaClass    string
	CoverMetaClassV   string
	CoverSystems      string
	CoverConfTitle    string
	CoverConfBody     string

	// executive summary
	SecExecSummary       string
	H2OverallRisk        string
	BodyOverallRisk      string
	ColSystem            string
	ColRiskScore         string
	ColCritical          string
	ColHigh              string
	ColMedium            string
	H2ComplianceMatrix   string
	BodyComplianceMatrix string
	ColArticle           string
	ColTitle             string
	ColStatus            string
	ColControls          string
	ColIssues            string
	H2StatusDefs         string
	LegendRows           [5][2]string // [label, description] for each status

	// scope section
	SecScope            string
	H2SystemsInScope    string
	BodySystemsInScope  string
	H2Methodology       string
	BodyMethodology1    string
	BodyMethodology2    string
	Activities          []string
	H2Limitations       string
	Limitations         []string
	H2ComplianceBasis   string
	BodyComplianceBasis string

	// article section
	SecArticleAnalysis string // printf with section number %d
	ArticleIntro       string
	H3Controls         string
	NoControls         string
	H3Violations       string
	NoViolations       string
	H3Obligations      string

	// client-application sub-sections within each article
	LabelIdpSystems    string // group header in risk table
	LabelClientSystems string // group header in risk table
	H3ClientSection    string // sub-section banner in article
	H3ClientControls   string
	H3ClientViolations string
	NoClientControls   string
	NoClientViolations string
	NoClientScanned    string // shown when no client was assessed

	// remediation section
	SecRemediation    string
	BodyRemediation   string
	ColNumber         string
	ColSeverity       string
	ColFinding        string
	ColHost           string
	NoViolationsFound string
	H2RemTimeline     string
	TimelineRows      [4][2]string

	// appendix
	SecAppendix       string
	AppendixIntro     string
	RiskScoreLabel    string // printf with %d
	NoFindingsForHost string

	// finding card
	CardRecommendation string
	CardMetaFmt        string // printf: host, module, confidence
	CardNIS2Prefix     string
}

func newStrings(lang string) pdfStrings {
	if lang == "de" {
		return deStrings()
	}
	return enStrings()
}

func enStrings() pdfStrings {
	return pdfStrings{
		HeaderTitle:     "Idenaro - NIS2 Compliance Assessment Report",
		HeaderConf:      "CONFIDENTIAL",
		FooterDirective: "NIS2 Directive (EU) 2022/2555 | IAM Assessment",
		FooterPage:      "Page %d of {nb}",

		StatusNonCompliant:      "NON-COMPLIANT",
		StatusRequiresAttention: "REQUIRES ATTENTION",
		StatusLargelyCompliant:  "LARGELY COMPLIANT",
		StatusCompliant:         "COMPLIANT",
		StatusNotAssessed:       "NOT ASSESSED",

		CoverPlatform:     "IAM Security Assessment Platform",
		CoverReportSub:    "Assessment Report",
		CoverDirective:    "Directive (EU) 2022/2555 - Article 21 Cybersecurity Risk-Management Measures",
		CoverMetaDate:     "Report Date:",
		CoverMetaScanner:  "Scanner:",
		CoverMetaScannerV: "Idenaro IAM assessment",
		CoverMetaType:     "Assessment Type:",
		CoverMetaTypeV:    "External assessment - no credentials required",
		CoverMetaMethod:   "Methodology:",
		CoverMetaMethodV:  "Unauthenticated probe of publicly reachable identity endpoints",
		CoverMetaScope:    "Scope:",
		CoverMetaScopeV:   "%d system(s) assessed",
		CoverMetaClass:    "Classification:",
		CoverMetaClassV:   "CONFIDENTIAL - Restricted distribution",
		CoverSystems:      "Assessed Systems",
		CoverConfTitle:    "CONFIDENTIALITY NOTICE",
		CoverConfBody: "This document contains sensitive security assessment results. Distribution is restricted " +
			"to authorised personnel with a legitimate need to know. Do not copy, transmit, or store " +
			"this document on systems not approved for confidential information.",

		SecExecSummary: "Executive Summary",
		H2OverallRisk:  "Overall Risk Assessment",
		BodyOverallRisk: "The following table summarises the overall risk score per assessed system. " +
			"Scores range from 0 (no findings) to 100 (maximum risk across all categories). " +
			"Scores above 70 indicate critical risk requiring immediate remediation.",
		ColSystem:          "System",
		ColRiskScore:       "Risk Score",
		ColCritical:        "Critical",
		ColHigh:            "High",
		ColMedium:          "Medium",
		H2ComplianceMatrix: "NIS2 Article 21 Compliance Status",
		BodyComplianceMatrix: "The following matrix summarises the compliance status for each assessed NIS2 " +
			"Art. 21(2) sub-paragraph. Statuses are derived exclusively from technical " +
			"findings produced by the assessment.",
		ColArticle:   "Article",
		ColTitle:     "Title",
		ColStatus:    "Status",
		ColControls:  "Controls",
		ColIssues:    "Issues",
		H2StatusDefs: "Status Definitions",
		LegendRows: [5][2]string{
			{"COMPLIANT", "Only informational findings (controls verified). No compliance gaps detected."},
			{"LARGELY COMPLIANT", "Only Low-severity findings. Minor improvements recommended."},
			{"REQUIRES ATTENTION", "Medium-severity findings present. Corrective action required within a defined timeframe."},
			{"NON-COMPLIANT", "High or Critical findings present. Immediate remediation required."},
			{"NOT ASSESSED", "No findings generated for this article. Insufficient data to determine compliance status."},
		},

		SecScope:           "Assessment Scope and Methodology",
		H2SystemsInScope:   "Systems in Scope",
		BodySystemsInScope: "The following systems were included in this security assessment:",
		H2Methodology:      "Assessment Methodology",
		BodyMethodology1: "This assessment was conducted using the Idenaro IAM security scanner. " +
			"All probes are unauthenticated and require no credentials or prior knowledge of " +
			"internal systems. The scanner examines publicly reachable identity infrastructure " +
			"from the perspective of an external, unprivileged observer.",
		BodyMethodology2: "Assessment activities included:",
		Activities: []string{
			"OIDC / OpenID Connect configuration analysis (discovery endpoints, algorithm enforcement, PKCE)",
			"SAML metadata and assertion security checks (signing, encryption, redirect validation)",
			"Multi-factor authentication presence and bypass resistance probing",
			"HTTP security header enumeration (HSTS, CSP, X-Frame-Options, Referrer-Policy)",
			"TLS configuration analysis (protocol versions, cipher suites, certificate validity)",
			"Session cookie security attribute inspection (Secure, HttpOnly, SameSite)",
			"CORS policy origin allowlist verification",
			"OAuth2 / OIDC callback endpoint state parameter validation",
			"User enumeration resistance testing on authentication flows",
			"Admin and debug endpoint exposure detection",
			"SCIM provisioning endpoint authentication checks",
			"Token lifecycle and revocation endpoint assessment",
			"Relying party application token validation probing",
		},
		H2Limitations: "Scope Limitations",
		Limitations: []string{
			"This is a unauthenticated assessment. Findings represent externally observable security posture only.",
			"Authenticated application flows, internal APIs, and post-login security controls are outside the scope of this assessment.",
			"Token validation checks using Bearer JWT probes are inconclusive for endpoints that use cookie-based sessions rather than Bearer authentication.",
			"The absence of a finding does not guarantee the absence of a vulnerability; only observable external behaviour is assessed.",
			"This report does not replace a comprehensive penetration test or source-code security review.",
		},
		H2ComplianceBasis: "Compliance Mapping Basis",
		BodyComplianceBasis: "All findings are mapped to NIS2 Directive (EU) 2022/2555, Article 21(2), sub-paragraphs " +
			"(a), (d), (e), (g), (h), (i), and (j). The mapping is based on the technical nature of " +
			"each finding and its relationship to the security measures mandated by each sub-paragraph. " +
			"Sub-paragraphs (b), (c), and (f) address incident management, business continuity, and " +
			"policy evaluation respectively; these are outside the scope of technical IAM assessment.",

		SecArticleAnalysis: "%d. NIS2 Article 21 Compliance Analysis",
		ArticleIntro: "This section provides a detailed compliance assessment for each applicable " +
			"NIS2 Art. 21(2) sub-paragraph. Identity provider findings and client application " +
			"findings are evaluated separately. The overall compliance status reflects the " +
			"worst-case result across both components.",
		H3Controls:    "Identity Provider - Controls Verified",
		NoControls:    "No controls verified for this article in the current scan.",
		H3Violations:  "Identity Provider - Violations Identified",
		NoViolations:  "No compliance violations identified for this article.",
		H3Obligations: "Compliance Obligations (Art. 21(2) Requirements)",

		LabelIdpSystems:    "Identity Providers",
		LabelClientSystems: "Client Applications",
		H3ClientSection:    "Client Application Assessment",
		H3ClientControls:   "Client Application - Controls Verified",
		H3ClientViolations: "Client Application - Violations Identified",
		NoClientControls:   "No controls verified for the client application in this article.",
		NoClientViolations: "No compliance violations identified for the client application.",
		NoClientScanned:    "No client application was included in this assessment.",

		SecRemediation: "Remediation Roadmap",
		BodyRemediation: "The following table lists all compliance violations in priority order. " +
			"Critical and High findings require immediate remediation. Medium findings " +
			"must be addressed within a defined remediation timeline documented in the " +
			"organisation's risk register. Low findings should be resolved as part of " +
			"routine security maintenance.",
		ColNumber:         "#",
		ColSeverity:       "Severity",
		ColFinding:        "Finding",
		ColHost:           "Host",
		NoViolationsFound: "No compliance violations found. All assessed controls are in a compliant state.",
		H2RemTimeline:     "Recommended Remediation Timeline",
		TimelineRows: [4][2]string{
			{"CRITICAL findings:", "Immediate - within 24-72 hours. Escalate to CISO. Document in risk register with incident status."},
			{"HIGH findings:", "Short-term - within 14 days. Assign owner, define mitigation steps, track to closure."},
			{"MEDIUM findings:", "Medium-term - within 60 days. Include in sprint backlog or next maintenance window."},
			{"LOW findings:", "Long-term - within 90 days or next major release. Acceptable as accepted risk with documented justification."},
		},

		SecAppendix: "Appendix A: Full Technical Findings",
		AppendixIntro: "This appendix contains the complete set of findings produced by the assessment, " +
			"including informational findings that document controls verified to be in place. " +
			"Findings are grouped by assessed system.",
		RiskScoreLabel:    "Risk Score: %d / 100",
		NoFindingsForHost: "No findings for this host.",

		CardRecommendation: "Recommendation:",
		CardMetaFmt:        "Host: %s  |  Module: %s  |  Confidence: %s",
		CardNIS2Prefix:     "NIS2: ",
	}
}
