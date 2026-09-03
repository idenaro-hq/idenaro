package report

import (
	"fmt"
	"strings"
)

// ─── Appendix A: Full Technical Findings ─────────────────────────────────────

func (b *pb) appendixSection(results []pdfScanResult) {
	s := b.s
	b.newPage()
	b.sectionBanner(enc(s.SecAppendix))

	b.pdf.SetFont("Helvetica", "", 10)
	b.pdf.SetTextColor(71, 85, 105)
	b.pdf.MultiCell(b.bw, 5.5, enc(s.AppendixIntro), "", "L", false)
	b.ln(5)

	for _, r := range results {
		b.checkBreak(20)

		// Host header
		b.pdf.SetFillColor(30, 58, 138)
		b.pdf.SetDrawColor(30, 58, 138)
		y := b.pdf.GetY()
		b.pdf.Rect(b.lm, y, b.bw, 9, "F")
		b.pdf.SetTextColor(255, 255, 255)
		b.pdf.SetFont("Helvetica", "B", 10)
		b.pdf.SetXY(b.lm+3, y+1.5)
		b.pdf.CellFormat(100, 6, enc(r.Host), "", 0, "L", false, 0, "")
		b.pdf.SetFont("Helvetica", "", 9)
		b.pdf.CellFormat(64, 6, enc(fmt.Sprintf(s.RiskScoreLabel, r.Score)), "", 1, "R", false, 0, "")
		b.pdf.Ln(3)

		if len(r.Findings) == 0 {
			b.pdf.SetFont("Helvetica", "I", 9)
			b.pdf.SetTextColor(148, 163, 184)
			b.pdf.SetX(b.lm)
			b.pdf.CellFormat(b.bw, 6, enc(s.NoFindingsForHost), "", 1, "L", false, 0, "")
		} else {
			for _, f := range r.Findings {
				isViolation := strings.ToUpper(f.Severity) != "INFO" && !f.IsChain
				b.findingCard(r.Host, f, isViolation)
			}
		}
		b.ln(4)
	}
}
