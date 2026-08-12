package finding_test

import (
	"testing"

	"idenaro/internal/finding"
)

func TestNewFinding(t *testing.T) {
	f := finding.NewFinding("oidc", "auth.example.com", "PKCE not supported", "Desc", finding.Medium)

	if f.Module != "oidc" {
		t.Errorf("expected module oidc, got %s", f.Module)
	}
	if f.Host != "auth.example.com" {
		t.Errorf("expected host auth.example.com, got %s", f.Host)
	}
	if f.Severity != finding.Medium {
		t.Errorf("expected MEDIUM, got %s", f.Severity)
	}
	if f.ID == "" {
		t.Error("ID should not be empty")
	}
}

func TestFindingWeight(t *testing.T) {
	cases := []struct {
		sev    finding.Severity
		minVal int
	}{
		{finding.Critical, 5},
		{finding.High, 4},
		{finding.Medium, 3},
		{finding.Low, 2},
		{finding.Info, 1},
	}
	for _, c := range cases {
		f := finding.Finding{Severity: c.sev}
		if f.Weight() != c.minVal {
			t.Errorf("severity %s: expected weight %d, got %d", c.sev, c.minVal, f.Weight())
		}
	}
}
