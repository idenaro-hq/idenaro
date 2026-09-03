package nis2_test

import (
	"testing"

	"idenaro/internal/nis2"
)

func TestLookup_SingleTag(t *testing.T) {
	articles := nis2.Lookup([]string{"mfa"})
	if len(articles) != 1 {
		t.Errorf("expected exactly 1 article for 'mfa', got %d: %v", len(articles), articles)
	}
}

func TestLookup_DeduplicatesAcrossTags(t *testing.T) {
	// oidc and saml both map to Art. 21(2)(j) - should deduplicate to one article
	articles := nis2.Lookup([]string{"oidc", "saml"})
	if len(articles) != 1 {
		t.Errorf("expected 1 deduplicated article for oidc+saml, got %d: %v", len(articles), articles)
	}
}

func TestLookup_UnknownTag(t *testing.T) {
	articles := nis2.Lookup([]string{"nonexistent-tag"})
	if len(articles) != 0 {
		t.Errorf("expected empty result for unknown tag, got %v", articles)
	}
}

func TestLookup_Empty(t *testing.T) {
	articles := nis2.Lookup([]string{})
	if len(articles) != 0 {
		t.Errorf("expected empty result for empty input, got %v", articles)
	}
}

func TestLookup_MixedGroups(t *testing.T) {
	// admin-exposure (i) + mfa (j) + tls (h) - three distinct articles, no overlap
	articles := nis2.Lookup([]string{"admin-exposure", "mfa", "tls"})
	if len(articles) != 3 {
		t.Errorf("expected 3 distinct articles, got %d: %v", len(articles), articles)
	}
}

func TestLookup_TypicalFinding(t *testing.T) {
	// A finding tagged admin-exposure + iam + endpoints previously produced 5 articles.
	// With one-primary-per-tag, admin-exposure and iam both resolve to (i),
	// endpoints resolves to (e) - result should be exactly 2.
	articles := nis2.Lookup([]string{"admin-exposure", "iam", "endpoints"})
	if len(articles) != 2 {
		t.Errorf("expected 2 articles for admin-exposure+iam+endpoints, got %d: %v", len(articles), articles)
	}
}
