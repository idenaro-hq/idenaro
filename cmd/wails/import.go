package main

import (
	"encoding/json"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// OpenImportJSON opens a native file dialog, reads the chosen JSON file, and
// returns its contents as []ScanResultDTO. Supports both the exported
// JSONReport format (snake_case) and direct ScanResultDTO arrays (camelCase).
// Returns nil if the user cancels, the file cannot be read, or parsing fails.
func (a *App) OpenImportJSON() []ScanResultDTO {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Import JSON Report",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON Reports (*.json)", Pattern: "*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// Try the exported JSONReport format first (has top-level "results" array).
	var rpt jsonImportReport
	if json.Unmarshal(data, &rpt) == nil && len(rpt.Results) > 0 {
		return importFromJSONReport(rpt)
	}
	// Fall back to a direct ScanResultDTO array (camelCase frontend format).
	var dtos []ScanResultDTO
	if json.Unmarshal(data, &dtos) == nil && len(dtos) > 0 {
		return dtos
	}
	return nil
}

// ── Import types (snake_case JSON report format) ──────────────────────────────

type jsonImportReport struct {
	Results []jsonImportHost `json:"results"`
}

type jsonImportHost struct {
	Host         string              `json:"host"`
	OverallScore int                 `json:"overall_score"`
	Duration     string              `json:"duration"`
	Findings     []jsonImportFinding `json:"findings"`
	FindingCount struct {
		Critical int `json:"critical"`
		High     int `json:"high"`
		Medium   int `json:"medium"`
		Low      int `json:"low"`
		Info     int `json:"info"`
		Total    int `json:"total"`
	} `json:"finding_count"`
}

type jsonImportFinding struct {
	ID             string   `json:"id"`
	Module         string   `json:"module"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	RiskScore      int      `json:"risk_score"`
	Evidence       []string `json:"evidence"`
	Recommendation string   `json:"recommendation"`
	NIS2Articles   []string `json:"nis2_articles"`
	Tags           []string `json:"tags"`
}

func importFromJSONReport(rpt jsonImportReport) []ScanResultDTO {
	dtos := make([]ScanResultDTO, 0, len(rpt.Results))
	for _, h := range rpt.Results {
		dto := ScanResultDTO{
			Host:         h.Host,
			OverallScore: h.OverallScore,
			Duration:     h.Duration,
			Findings:     make([]FindingDTO, 0, len(h.Findings)),
			Counts: CountsDTO{
				Critical: h.FindingCount.Critical,
				High:     h.FindingCount.High,
				Medium:   h.FindingCount.Medium,
				Low:      h.FindingCount.Low,
				Info:     h.FindingCount.Info,
				Total:    h.FindingCount.Total,
			},
		}
		for _, f := range h.Findings {
			isChain := f.Module == "chain"
			if isChain {
				dto.Counts.Chain++
			}
			dto.Findings = append(dto.Findings, FindingDTO{
				ID:             f.ID,
				Module:         f.Module,
				Title:          f.Title,
				Description:    f.Description,
				Severity:       f.Severity,
				Confidence:     f.Confidence,
				RiskScore:      f.RiskScore,
				Evidence:       nullsafe(f.Evidence),
				Recommendation: f.Recommendation,
				NIS2Articles:   nullsafe(f.NIS2Articles),
				Tags:           nullsafe(f.Tags),
				IsChain:        isChain,
			})
		}
		dtos = append(dtos, dto)
	}
	return dtos
}
