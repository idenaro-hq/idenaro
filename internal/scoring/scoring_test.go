package scoring_test

import (
	"fmt"
	"strings"
	"testing"

	"idenaro/internal/finding"
	"idenaro/internal/scoring"
)

func TestScore_CriticalHigh(t *testing.T) {
	f := finding.NewFinding("test", "host", "title", "desc", finding.Critical)
	f.Confidence = "HIGH"
	scoring.Score(&f)
	if f.RiskScore != 90 {
		t.Errorf("expected 90, got %d", f.RiskScore)
	}
}

func TestScore_HighMediumConfidence(t *testing.T) {
	f := finding.NewFinding("test", "host", "title", "desc", finding.High)
	f.Confidence = "MEDIUM"
	scoring.Score(&f)
	// 70 * 0.75 = 52
	if f.RiskScore != 52 {
		t.Errorf("expected 52, got %d", f.RiskScore)
	}
}

func TestScore_InfoLow(t *testing.T) {
	f := finding.NewFinding("test", "host", "title", "desc", finding.Info)
	f.Confidence = "LOW"
	scoring.Score(&f)
	if f.RiskScore != 0 {
		t.Errorf("expected 0, got %d", f.RiskScore)
	}
}

func TestOverallScore_Empty(t *testing.T) {
	score := scoring.OverallScore(nil)
	if score != 0 {
		t.Errorf("expected 0 for empty findings, got %d", score)
	}
}

func TestOverallScore_Mixed(t *testing.T) {
	findings := []finding.Finding{
		{Severity: finding.Critical, RiskScore: 90},
		{Severity: finding.High, RiskScore: 70},
		{Severity: finding.Medium, RiskScore: 45},
	}
	score := scoring.OverallScore(findings)
	// totalPenalty = 90*1.0 + 70*0.8 + 45*0.5 = 168.5
	// score = int((168.5 / 900) * 100) = 18
	if score != 18 {
		t.Errorf("expected 18, got %d", score)
	}
}

// taggedFindingSeq generates unique IDs across a test so that the scoring
// deduplication in collectMatchingFindings does not skip genuine duplicates.
var taggedFindingSeq int

// makeTaggedFinding builds a pre-scored finding with the given tags.
// Each call produces a distinct ID so deduplication in ApplyChaining works
// correctly when the same tag appears across two real findings.
func makeTaggedFinding(sev finding.Severity, riskScore int, tags ...string) finding.Finding {
	taggedFindingSeq++
	title := fmt.Sprintf("finding-%d", taggedFindingSeq)
	f := finding.NewFinding("test", "host", title, "desc", sev)
	f.RiskScore = riskScore
	f.Tags = append(f.Tags, tags...)
	return f
}

// TestChain_AllInfoSkipped verifies that a chain does not fire when every
// contributing finding is INFO severity. INFO findings cannot satisfy slots.
func TestChain_AllInfoSkipped(t *testing.T) {
	findings := []finding.Finding{
		makeTaggedFinding(finding.Info, 0, "admin-exposure"),
		makeTaggedFinding(finding.Info, 0, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			t.Errorf("chain must not fire when all contributors are INFO: got %q (score %d)", f.Title, f.RiskScore)
		}
	}
}

// TestChain_InfoSlotDoesNotSatisfy verifies that a slot satisfied only by an
// INFO finding is treated as unsatisfied - the chain must not fire.
func TestChain_InfoSlotDoesNotSatisfy(t *testing.T) {
	// Slot 1 ("admin-exposure") has a HIGH finding → satisfied.
	// Slot 2 ("cookies"/"headers") has only an INFO finding → NOT satisfied.
	// Rule: "Exposed admin panel + missing authentication controls" (Critical).
	findings := []finding.Finding{
		makeTaggedFinding(finding.High, 70, "admin-exposure"),
		makeTaggedFinding(finding.Info, 0, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			t.Errorf("chain fired despite INFO-only slot contributor: %q (score %d)", f.Title, f.RiskScore)
		}
	}
}

// TestChain_ScoreAnchoredToRuleSeverity verifies that chain score is anchored
// to the attack outcome the rule defines (ChainSeverity), not the arithmetic
// sum of individual contributors. A High-designated chain with two MEDIUM
// contributors must score in the High range - not Critical.
func TestChain_ScoreAnchoredToRuleSeverity(t *testing.T) {
	// "Missing HSTS + insecure cookie flags" is a High-designated chain.
	// Two MEDIUM contributors (score 40 each):
	//   base = 70 (High), evidenceScore = 80, bonus = min(int(80*0.05), 15) = 4
	//   chainScore = 74 → High (55-79)
	findings := []finding.Finding{
		makeTaggedFinding(finding.Medium, 40, "headers"),
		makeTaggedFinding(finding.Medium, 40, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			if f.Severity != finding.High {
				t.Errorf("expected HIGH severity for High-designated chain with MEDIUM contributors, got %s", f.Severity)
			}
			if f.RiskScore < 55 || f.RiskScore >= 80 {
				t.Errorf("expected chain score in High range [55,79], got %d", f.RiskScore)
			}
			return
		}
	}
	t.Error("expected a chain finding, got none")
}

// TestChain_CriticalRuleAlwaysScoresCritical verifies that a Critical-designated
// chain always produces a Critical-level score regardless of contributor strength.
func TestChain_CriticalRuleAlwaysScoresCritical(t *testing.T) {
	// "Exposed admin panel" is Critical-designated: base = 90.
	// Even with only MEDIUM contributors, score = 90 + bonus → capped at 90 → Critical.
	findings := []finding.Finding{
		makeTaggedFinding(finding.Medium, 40, "admin-exposure"),
		makeTaggedFinding(finding.Medium, 40, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			if f.Severity != finding.Critical {
				t.Errorf("expected CRITICAL severity for Critical-designated chain, got %s", f.Severity)
			}
			if f.RiskScore != 90 {
				t.Errorf("expected chain score 90 (Critical base, capped), got %d", f.RiskScore)
			}
			return
		}
	}
	t.Error("expected a chain finding, got none")
}

// TestChain_StrongEvidenceAddsBonus verifies that strong contributors push the
// chain score above the rule's base - up to the +15 cap. A High rule with two
// Critical contributors should score higher than 70 (base) but ≤ 85 (70+15).
func TestChain_StrongEvidenceAddsBonus(t *testing.T) {
	// "Missing HSTS + insecure cookie flags" (High, base=70).
	// Two CRITICAL contributors (90 each): evidenceScore=180, bonus=min(9,15)=9
	// chainScore = 79 → still High (not Critical), bonus correctly applied.
	findings := []finding.Finding{
		makeTaggedFinding(finding.Critical, 90, "headers"),
		makeTaggedFinding(finding.Critical, 90, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			if f.RiskScore <= 70 {
				t.Errorf("expected chain score > 70 (evidence bonus applied), got %d", f.RiskScore)
			}
			if f.RiskScore > 85 {
				t.Errorf("expected chain score ≤ 85 (bonus capped at +15), got %d", f.RiskScore)
			}
			return
		}
	}
	t.Error("expected a chain finding, got none")
}

// TestChain_ScoreCappedAt90 verifies the absolute cap at 90 holds for all chains.
func TestChain_ScoreCappedAt90(t *testing.T) {
	// Critical-designated chain (base already 90); adding bonus would exceed 90.
	findings := []finding.Finding{
		makeTaggedFinding(finding.Critical, 90, "admin-exposure"),
		makeTaggedFinding(finding.Critical, 90, "cookies"),
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			if f.RiskScore != 90 {
				t.Errorf("expected chain score capped at 90, got %d", f.RiskScore)
			}
			return
		}
	}
	t.Error("expected a chain finding, got none")
}

// TestChain_InfoExcludedFromEvidence verifies that INFO findings are not
// included in the chain's evidence list even when non-INFO findings fire the chain.
func TestChain_InfoExcludedFromEvidence(t *testing.T) {
	// Both slots satisfied by non-INFO findings; extra INFO findings share the tags.
	// INFO must not appear in evidence.
	findings := []finding.Finding{
		makeTaggedFinding(finding.High, 70, "headers"),
		makeTaggedFinding(finding.Info, 0, "headers"), // same tag, INFO - excluded
		makeTaggedFinding(finding.Medium, 40, "cookies"),
		makeTaggedFinding(finding.Info, 0, "cookies"), // same tag, INFO - excluded
	}
	result := scoring.ApplyChaining(findings)
	for _, f := range result {
		if f.Module == "chain" {
			for _, ev := range f.Evidence {
				if strings.HasSuffix(ev, "[INFO]") {
					t.Errorf("INFO finding appeared in chain evidence: %q", ev)
				}
			}
			return
		}
	}
	t.Error("expected a chain finding, got none")
}
