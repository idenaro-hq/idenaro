package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"idenaro/internal/nis2"
)

// ─── Internal DTO types ───────────────────────────────────────────────────────

type pdfScanResult struct {
	Host     string       `json:"host"`
	Score    int          `json:"overallScore"`
	Duration string       `json:"duration"`
	Findings []pdfFinding `json:"findings"`
	Counts   pdfCounts    `json:"counts"`
}

type pdfFinding struct {
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

type pdfCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
	Chain    int `json:"chain"`
}

// ─── Compliance status ────────────────────────────────────────────────────────

type compStatus struct {
	key     string // language-independent key used for label lookup
	r, g, b int
}

var (
	csNonCompliant      = compStatus{"NON_COMPLIANT", 220, 38, 38}
	csRequiresAttention = compStatus{"REQUIRES_ATTENTION", 200, 100, 5}
	csLargelyCompliant  = compStatus{"LARGELY_COMPLIANT", 101, 163, 13}
	csCompliant         = compStatus{"COMPLIANT", 22, 163, 74}
	csNotAssessed       = compStatus{"NOT_ASSESSED", 148, 163, 184}
)

type hostedFinding struct {
	Host string
	F    pdfFinding
}

type articleReport struct {
	Art              nis2.Article
	Controls         []hostedFinding // IdP controls
	Violations       []hostedFinding // IdP violations
	ClientControls   []hostedFinding // client-app controls
	ClientViolations []hostedFinding // client-app violations
	Status           compStatus      // overall (IdP + client combined)
	ClientStatus     compStatus      // client-only
}

// isClientResult returns true when all non-empty findings originate from the
// "client" module, identifying the result as a relying-party scan.
func isClientResult(r pdfScanResult) bool {
	for _, f := range r.Findings {
		if f.Module == "client" {
			return true
		}
	}
	return false
}

// ─── Article report building ──────────────────────────────────────────────────

func buildArticleReports(results []pdfScanResult) []articleReport {
	byID := make(map[string]*articleReport, len(nis2.Articles))
	for i := range nis2.Articles {
		a := nis2.Articles[i]
		byID[a.ID] = &articleReport{Art: a, Status: csNotAssessed, ClientStatus: csNotAssessed}
	}
	for _, r := range results {
		client := isClientResult(r)
		for _, f := range r.Findings {
			hf := hostedFinding{Host: r.Host, F: f}
			isInfo := strings.ToUpper(f.Severity) == "INFO"
			for _, ref := range f.NIS2Articles {
				id := nis2.RefToID(ref)
				if id == "" {
					continue
				}
				ar, ok := byID[id]
				if !ok {
					continue
				}
				if client {
					if isInfo {
						ar.ClientControls = append(ar.ClientControls, hf)
					} else {
						ar.ClientViolations = append(ar.ClientViolations, hf)
					}
				} else {
					if isInfo {
						ar.Controls = append(ar.Controls, hf)
					} else {
						ar.Violations = append(ar.Violations, hf)
					}
				}
			}
		}
	}
	for _, ar := range byID {
		// Overall status is worst-case across both sources.
		allViolations := append(ar.Violations, ar.ClientViolations...)
		allControls := append(ar.Controls, ar.ClientControls...)
		ar.Status = deriveStatus(allViolations, allControls)
		ar.ClientStatus = deriveStatus(ar.ClientViolations, ar.ClientControls)
	}
	out := make([]articleReport, 0, len(nis2.Articles))
	for i := range nis2.Articles {
		out = append(out, *byID[nis2.Articles[i].ID])
	}
	return out
}

func deriveStatus(violations, controls []hostedFinding) compStatus {
	if len(violations) == 0 && len(controls) == 0 {
		return csNotAssessed
	}
	for _, v := range violations {
		s := strings.ToUpper(v.F.Severity)
		if s == "CRITICAL" || s == "HIGH" {
			return csNonCompliant
		}
	}
	for _, v := range violations {
		if strings.ToUpper(v.F.Severity) == "MEDIUM" {
			return csRequiresAttention
		}
	}
	if len(violations) > 0 {
		return csLargelyCompliant
	}
	return csCompliant
}

// ─── PDF builder ─────────────────────────────────────────────────────────────

type pb struct {
	pdf      *fpdf.Fpdf
	bw       float64 // body width (170 mm on A4)
	lm       float64 // left margin
	section  int
	scanDate string
	lang     string
	s        pdfStrings
}

// WriteCompliancePDF generates a NIS2 compliance PDF and writes it to w.
// resultsJSON is the JSON-serialised []ScanResultDTO from the Wails frontend.
// lang is "en" or "de".
func WriteCompliancePDF(w io.Writer, resultsJSON []byte, lang string) error {
	var results []pdfScanResult
	if err := json.Unmarshal(resultsJSON, &results); err != nil {
		return fmt.Errorf("compliance-pdf: parse results: %w", err)
	}

	artReports := buildArticleReports(results)

	b := &pb{
		bw:       170,
		lm:       20,
		scanDate: time.Now().Format("2006-01-02"),
		lang:     lang,
		s:        newStrings(lang),
	}
	b.init()
	b.cover(results)
	b.execSummary(results, artReports)
	b.scopeSection(results)
	b.articleSections(artReports)
	b.remediationSection(results)
	b.appendixSection(results)

	return b.pdf.Output(w)
}

// ─── Initialisation ───────────────────────────────────────────────────────────

func (b *pb) init() {
	pdf := fpdf.New("P", "mm", "A4", "")
	b.pdf = pdf
	pdf.SetMargins(20, 25, 20)
	pdf.SetAutoPageBreak(true, 22)
	pdf.AliasNbPages("{nb}")
	pdf.SetTitle("NIS2 Compliance Assessment Report", true)
	pdf.SetSubject("NIS2 Directive (EU) 2022/2555 - Art. 21 Assessment", true)
	pdf.SetAuthor("Idenaro IAM Security Scanner", true)
	pdf.SetCreator("Idenaro", true)

	s := b.s
	pdf.SetHeaderFunc(func() {
		if pdf.PageNo() <= 1 {
			return
		}
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(100, 116, 139)
		pdf.SetXY(20, 12)
		pdf.CellFormat(90, 5, enc(s.HeaderTitle), "", 0, "L", false, 0, "")
		pdf.CellFormat(80, 5, enc(s.HeaderConf), "", 1, "R", false, 0, "")
		pdf.SetDrawColor(203, 213, 225)
		pdf.Line(20, 18, 190, 18)
	})

	pdf.SetFooterFunc(func() {
		if pdf.PageNo() <= 1 {
			return
		}
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(100, 116, 139)
		pdf.CellFormat(120, 10, enc(s.FooterDirective), "", 0, "L", false, 0, "")
		pdf.CellFormat(50, 10,
			fmt.Sprintf(enc(s.FooterPage), pdf.PageNo()),
			"", 0, "R", false, 0, "")
	})
}

// statusLabel returns the localised display label for a compliance status.
func (b *pb) statusLabel(cs compStatus) string {
	switch cs.key {
	case "NON_COMPLIANT":
		return b.s.StatusNonCompliant
	case "REQUIRES_ATTENTION":
		return b.s.StatusRequiresAttention
	case "LARGELY_COMPLIANT":
		return b.s.StatusLargelyCompliant
	case "COMPLIANT":
		return b.s.StatusCompliant
	case "NOT_ASSESSED":
		return b.s.StatusNotAssessed
	default:
		return cs.key
	}
}
