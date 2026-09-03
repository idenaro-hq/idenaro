package main

import (
	"time"

	"idenaro/internal/engine"
	"idenaro/internal/finding"
)

// ── Wire DTOs ─────────────────────────────────────────────────────────────────
// These types are serialised to JSON and sent to the frontend. Field names must
// match what the TypeScript models.ts declares.

type ScanResultDTO struct {
	Host         string       `json:"host"`
	OverallScore int          `json:"overallScore"`
	Duration     string       `json:"duration"`
	Error        string       `json:"error,omitempty"`
	Findings     []FindingDTO `json:"findings"`
	Counts       CountsDTO    `json:"counts"`
}

type FindingDTO struct {
	ID             string   `json:"id"`
	Module         string   `json:"module"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	RiskScore      int      `json:"riskScore"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	NIS2Articles   []string `json:"nis2Articles"`
	Tags           []string `json:"tags"`
	IsChain        bool     `json:"isChain"`
}

type CountsDTO struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
	Chain    int `json:"chain"`
}

// ScanProgressEvent is emitted on "scan:module:done" as each module completes.
type ScanProgressEvent struct {
	Host   string `json:"host"`
	Module string `json:"module"`
	Done   int    `json:"done"`
	Total  int    `json:"total"`
}

// ── Conversion ────────────────────────────────────────────────────────────────

// toDTO converts engine results to the wire format consumed by the frontend.
func toDTO(results []engine.ScanResult) []ScanResultDTO {
	dtos := make([]ScanResultDTO, 0, len(results))
	for _, r := range results {
		dto := ScanResultDTO{
			Host:         r.Host,
			OverallScore: r.OverallScore,
			Duration:     r.Duration.Round(time.Millisecond).String(),
			Findings:     make([]FindingDTO, 0, len(r.Findings)),
		}
		if r.Error != nil {
			dto.Error = r.Error.Error()
		}

		counts := CountsDTO{Total: len(r.Findings)}
		for _, f := range r.Findings {
			isChain := f.Module == "chain"
			dto.Findings = append(dto.Findings, FindingDTO{
				ID:             f.ID,
				Module:         f.Module,
				Title:          f.Title,
				Description:    f.Description,
				Severity:       string(f.Severity),
				Confidence:     f.Confidence,
				RiskScore:      f.RiskScore,
				Evidence:       nullsafe(f.Evidence),
				Recommendation: f.Recommendation,
				NIS2Articles:   nullsafe(f.NIS2Articles),
				Tags:           nullsafe(f.Tags),
				IsChain:        isChain,
			})
			if isChain {
				counts.Chain++
				continue
			}
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
		dto.Counts = counts
		dtos = append(dtos, dto)
	}
	return dtos
}

// nullsafe converts a nil slice to an empty slice so JSON output is [] not null.
func nullsafe(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
