package checks

import "idenaro/internal/finding"

// SCIMPath defines a SCIM-related endpoint to probe.
type SCIMPath struct {
	Path        string
	Description string
	Severity    finding.Severity
}

// SCIMPaths is the ordered list of SCIM endpoints to probe.
var SCIMPaths = []SCIMPath{
	// Core SCIM v2 endpoints
	{"/scim/v2/Users", "SCIM v2 Users endpoint", finding.High},
	{"/scim/v2/Groups", "SCIM v2 Groups endpoint", finding.High},
	{"/scim/v2/ServiceProviderConfig", "SCIM v2 service provider config", finding.Medium},
	{"/scim/v2/ResourceTypes", "SCIM v2 resource types", finding.Low},
	{"/scim/v2/Schemas", "SCIM v2 schemas", finding.Low},
	{"/scim/v2", "SCIM v2 root", finding.Medium},

	// SCIM v1 (older deployments)
	{"/scim/v1/Users", "SCIM v1 Users endpoint", finding.High},
	{"/scim/v1/Groups", "SCIM v1 Groups endpoint", finding.High},
	{"/scim/v1", "SCIM v1 root", finding.Medium},

	// Common alternate paths
	{"/scim", "SCIM root", finding.Medium},
	{"/api/scim/v2/Users", "SCIM Users (API prefix)", finding.High},
	{"/api/scim/v2/Groups", "SCIM Groups (API prefix)", finding.High},

	// Okta-style
	{"/api/v1/users", "Okta users API", finding.High},
	{"/api/v1/groups", "Okta groups API", finding.High},

	// Keycloak
	{"/realms/master/users", "Keycloak users (master realm)", finding.High},

	// Azure AD SCIM proxy artifacts
	{"/provisioning/scim/Users", "Azure AD SCIM provisioning", finding.High},
}
