package scoring

import (
	"fmt"
	"sort"
	"strings"

	"idenaro/internal/finding"
)

// severityBaseScore maps each severity level to its raw risk penalty before
// confidence adjustment. Higher values produce larger score contributions.
var severityBaseScore = map[finding.Severity]int{
	finding.Critical: 90,
	finding.High:     70,
	finding.Medium:   40,
	finding.Low:      15,
	finding.Info:     0, // INFO findings carry no risk score
}

// confidenceMultiplier scales the base score down when a finding is not
// directly confirmed.
var confidenceMultiplier = map[string]float64{
	"HIGH":   1.0,
	"MEDIUM": 0.75,
	"LOW":    0.5,
}

const defaultConfidenceMultiplier = 0.75

// ScoreFinding calculates the risk penalty for a single finding and writes it
// back into f.RiskScore. Formula: baseScore × confidenceMultiplier.
func ScoreFinding(f *finding.Finding) {
	baseScore := severityBaseScore[f.Severity]
	multiplier, known := confidenceMultiplier[f.Confidence]
	if !known {
		multiplier = defaultConfidenceMultiplier
	}
	f.RiskScore = int(float64(baseScore) * multiplier)
}

// Score is an alias for ScoreFinding kept for test compatibility.
func Score(f *finding.Finding) { ScoreFinding(f) }

// ScoreAll applies ScoreFinding to every finding in the slice and returns
// the same slice for convenient chaining.
func ScoreAll(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		ScoreFinding(&findings[i])
	}
	return findings
}

// ChainRule describes a dangerous combination of finding tags whose combined
// risk exceeds the sum of the individual findings.
type ChainRule struct {
	// Name is the human-readable rule label used as the chain finding title.
	Name string

	// Description explains why this combination is more dangerous than the
	// individual findings in isolation.
	Description string

	// RequiredTagSlots is a 2D slice that expresses an AND-of-ORs condition:
	// every outer slot must be satisfied, and within each slot any one tag
	// from the inner slice is sufficient.
	RequiredTagSlots [][]string

	// MinMatchingFindings is the minimum number of distinct non-INFO findings
	// that must contribute before the rule fires.
	MinMatchingFindings int

	// ChainSeverity is the severity assigned to the synthetic chain finding.
	// It reflects the severity of the attack the chain enables - not the sum
	// of individual contributors. This anchors the score to the attack outcome
	// rather than to the arithmetic of its components (CVSS principle).
	ChainSeverity finding.Severity

	// DocID is the stable short ID that matches the chain's documentation and
	// translation entry (e.g. "chain-admin-session"). If empty the ID is derived
	// from the rule name.
	DocID string
}

// ApplyChaining evaluates every chain rule against the collected findings and
// appends a synthetic chain finding for each rule that fires. The original
// findings are returned unchanged; chain findings are appended at the end.
//
// Scoring rationale (CVSS-aligned):
//   - Chain severity is determined by the attack the chain ENABLES (ChainSeverity),
//     not by summing individual scores. A chain of LOW/MEDIUM findings that enables
//     privilege escalation is High - its severity is defined by the attack outcome.
//   - The numeric score is anchored to ChainSeverity's base score, then raised by
//     a small evidence bonus (≤ 15 points) proportional to contributor strength.
//   - INFO findings are excluded entirely: they carry no risk and must not trigger
//     or inflate chain conditions.
func ApplyChaining(findings []finding.Finding) []finding.Finding {
	var chainFindings []finding.Finding

	for _, rule := range chainRules {
		matched := collectMatchingFindings(findings, rule)
		if len(matched) < rule.MinMatchingFindings {
			continue
		}

		// Sort evidence by descending risk score for consistent ordering.
		sort.Slice(matched, func(i, j int) bool {
			return matched[i].RiskScore > matched[j].RiskScore
		})

		evidence := make([]string, 0, len(matched))
		recLines := make([]string, 0, len(matched))
		evidenceScore := 0
		for _, mf := range matched {
			evidence = append(evidence, fmt.Sprintf("%s [%s]", mf.Title, string(mf.Severity)))
			recLines = append(recLines, fmt.Sprintf("- %s", mf.Title))
			evidenceScore += mf.RiskScore
		}
		recommendation := "Remediate the contributing findings, starting with the highest severity:\n" +
			strings.Join(recLines, "\n")

		// Anchor score to rule's defined severity (the attack outcome tier).
		// Add an evidence bonus: 5% of total contributor score, capped at +15.
		// This means two MEDIUMs in a High-designated chain score ~74 (High),
		// while two Criticals in the same chain score ~79 (still High).
		// A Critical-designated chain always scores ≥ 90 regardless of contributors.
		baseScore := severityBaseScore[rule.ChainSeverity]
		bonus := int(float64(evidenceScore) * 0.05)
		if bonus > 15 {
			bonus = 15
		}
		chainScore := baseScore + bonus
		if chainScore > 90 {
			chainScore = 90
		}

		chainSeverity := scoreToSeverity(chainScore)

		chainID := "chain-" + nameToID(rule.Name)
		if rule.DocID != "" {
			chainID = rule.DocID
		}
		chainFinding := finding.Finding{
			ID:             chainID,
			Module:         "chain",
			Title:          "Chain: " + rule.Name,
			Description:    rule.Description,
			Severity:       chainSeverity,
			Confidence:     "HIGH",
			RiskScore:      chainScore,
			Tags:           []string{"chain"},
			Evidence:       evidence,
			Recommendation: recommendation,
		}
		chainFindings = append(chainFindings, chainFinding)
	}

	return append(findings, chainFindings...)
}

// OverallScore returns a risk score from 0-100 where:
//
//	0   = no findings, no danger
//	100 = maximum risk (all severity weights saturated)
func OverallScore(allFindings []finding.Finding) int {
	if len(allFindings) == 0 {
		return 0
	}

	severityPenaltyWeight := map[finding.Severity]float64{
		finding.Critical: 1.0,
		finding.High:     0.8,
		finding.Medium:   0.5,
		finding.Low:      0.25,
		finding.Info:     0.0,
	}

	totalPenalty := 0.0
	for _, f := range allFindings {
		penaltyWeight := severityPenaltyWeight[f.Severity]
		totalPenalty += float64(f.RiskScore) * penaltyWeight
	}

	const maxPenalty = 900.0
	if totalPenalty > maxPenalty {
		totalPenalty = maxPenalty
	}

	riskScore := int((totalPenalty / maxPenalty) * 100.0)
	if riskScore > 100 {
		riskScore = 100
	}
	return riskScore
}

// collectMatchingFindings returns all non-INFO findings whose tags intersect
// with the rule's required tags, but only when every slot is first satisfied
// by at least one non-INFO finding.
//
// INFO findings are excluded at both the slot-satisfaction check and the
// evidence-collection step. A chain must represent real risk; INFO findings
// carry no risk score and therefore cannot justify firing a chain finding.
func collectMatchingFindings(findings []finding.Finding, rule ChainRule) []finding.Finding {
	// Step 1: Verify every slot has at least one non-INFO finding with a matching tag.
	// The original code had a misplaced goto label - the nextSlot: label sat inside
	// the inner for-f loop, so goto advanced to the next finding rather than the
	// next slot, causing all matching findings to accumulate instead of one per slot.
	// This loop is explicit and avoids goto entirely.
	for _, tagOptions := range rule.RequiredTagSlots {
		slotSatisfied := false
		for _, f := range findings {
			if f.Severity == finding.Info {
				continue
			}
			for _, findingTag := range f.Tags {
				for _, requiredTag := range tagOptions {
					if findingTag == requiredTag {
						slotSatisfied = true
						break
					}
				}
				if slotSatisfied {
					break
				}
			}
			if slotSatisfied {
				break
			}
		}
		if !slotSatisfied {
			return nil
		}
	}

	// Step 2: Collect all non-INFO findings that carry any of the rule's required
	// tags. Showing all contributors gives better evidence context than one-per-slot,
	// while the INFO filter ensures only actionable findings appear.
	requiredTags := make(map[string]bool)
	for _, tagOptions := range rule.RequiredTagSlots {
		for _, tag := range tagOptions {
			requiredTags[tag] = true
		}
	}

	var matched []finding.Finding
	seen := make(map[string]bool)
	for _, f := range findings {
		if f.Severity == finding.Info {
			continue
		}
		for _, findingTag := range f.Tags {
			if requiredTags[findingTag] && !seen[f.ID] {
				matched = append(matched, f)
				seen[f.ID] = true
				break
			}
		}
	}
	return matched
}

// scoreToSeverity maps a numeric risk score back to a Severity label.
func scoreToSeverity(score int) finding.Severity {
	switch {
	case score >= 80:
		return finding.Critical
	case score >= 55:
		return finding.High
	case score >= 25:
		return finding.Medium
	case score >= 8:
		return finding.Low
	default:
		return finding.Info
	}
}

// nameToID converts a human-readable rule name into a URL-safe identifier.
func nameToID(name string) string {
	idBytes := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch == ' ' || ch == '/' || ch == '(' || ch == ')' || ch == '+':
			idBytes = append(idBytes, '-')
		case (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-':
			idBytes = append(idBytes, ch)
		}
	}
	return string(idBytes)
}
