package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"idenaro/internal/engine"
	"idenaro/internal/finding"
)

// JSONReport is the top-level structure written when --format json is used.
type JSONReport struct {
	Version     string           `json:"version"`
	GeneratedAt time.Time        `json:"generated_at"`
	Scanner     string           `json:"scanner"`
	Results     []JSONHostResult `json:"results"`
	Summary     JSONSummary      `json:"summary"`
}

// JSONHostResult holds findings and counts for a single scanned host.
type JSONHostResult struct {
	Host         string            `json:"host"`
	OverallScore int               `json:"overall_score"`
	Duration     string            `json:"duration"`
	Findings     []finding.Finding `json:"findings"`
	FindingCount JSONFindingCount  `json:"finding_count"`
}

// JSONFindingCount breaks down the finding total by severity level.
type JSONFindingCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// JSONSummary aggregates counts across all scanned hosts.
type JSONSummary struct {
	HostsScanned  int              `json:"hosts_scanned"`
	TotalFindings int              `json:"total_findings"`
	BySeverity    JSONFindingCount `json:"by_severity"`
}

// WriteJSON serialises all scan results to w as a JSON report. Set pretty to
// true for human-readable indented output; false for compact machine output.
func WriteJSON(w io.Writer, results []engine.ScanResult, pretty bool) error {
	reportData := buildJSONReport(results)

	encoder := json.NewEncoder(w)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(reportData); err != nil {
		return fmt.Errorf("report: JSON encode error: %w", err)
	}
	return nil
}

func buildJSONReport(results []engine.ScanResult) JSONReport {
	reportData := JSONReport{
		Version:     "1.0.0",
		GeneratedAt: time.Now().UTC(),
		Scanner:     "idenaro IAM Security Scanner",
		Results:     make([]JSONHostResult, 0, len(results)),
	}

	var aggregateCounts JSONFindingCount

	for _, scanResult := range results {
		hostCounts := countFindingsBySeverity(scanResult.Findings)

		aggregateCounts.Critical += hostCounts.Critical
		aggregateCounts.High += hostCounts.High
		aggregateCounts.Medium += hostCounts.Medium
		aggregateCounts.Low += hostCounts.Low
		aggregateCounts.Info += hostCounts.Info
		aggregateCounts.Total += hostCounts.Total

		hostFindings := scanResult.Findings
		if hostFindings == nil {
			hostFindings = []finding.Finding{}
		}

		reportData.Results = append(reportData.Results, JSONHostResult{
			Host:         scanResult.Host,
			OverallScore: scanResult.OverallScore,
			Duration:     scanResult.Duration.Round(time.Millisecond).String(),
			Findings:     hostFindings,
			FindingCount: hostCounts,
		})
	}

	reportData.Summary = JSONSummary{
		HostsScanned:  len(results),
		TotalFindings: aggregateCounts.Total,
		BySeverity:    aggregateCounts,
	}

	return reportData
}

func countFindingsBySeverity(findings []finding.Finding) JSONFindingCount {
	var counts JSONFindingCount
	for _, f := range findings {
		counts.Total++
		switch f.Severity {
		case finding.Critical:
			counts.Critical++
		case finding.High:
			counts.High++
		case finding.Medium:
			counts.Medium++
		case finding.Low:
			counts.Low++
		case finding.Info:
			counts.Info++
		}
	}
	return counts
}
