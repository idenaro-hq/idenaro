package checks

import "strings"

const moduleName = "cookies"

var authCookieNamePatterns = []string{
	"session", "sess", "jsessionid", "phpsessid", "asp.net_sessionid",
	"auth", "token", "jwt", "access_token", "id_token", "refresh",
	"keycloak", "kc_", "oidc", "saml", "sso", "login",
}

func IsAuthCookieName(cookieName string) bool {
	lowerName := strings.ToLower(cookieName)
	for _, pattern := range authCookieNamePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}
	return false
}
