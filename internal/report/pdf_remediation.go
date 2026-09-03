package report

import (
	"fmt"
	"sort"
	"strings"

	"idenaro/internal/nis2"
)

// ─── Section 4: Remediation Roadmap ──────────────────────────────────────────

func (b *pb) remediationSection(results []pdfScanResult) {
	s := b.s
	b.newSection(s.SecRemediation)
	b.bodyText(enc(s.BodyRemediation))
	b.ln(4)

	type remItem struct {
		host       string
		f          pdfFinding
		articleRef string
	}
	sevOrder := map[string]int{
		"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
	}

	var items []remItem
	for _, r := range results {
		for _, f := range r.Findings {
			sev := strings.ToUpper(f.Severity)
			if sev == "INFO" || f.IsChain {
				continue
			}
			ref := ""
			if len(f.NIS2Articles) > 0 {
				id := nis2.RefToID(f.NIS2Articles[0])
				if art, ok := nis2.FindByID(id); ok {
					ref = art.Number
				}
			}
			items = append(items, remItem{host: r.Host, f: f, articleRef: ref})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return sevOrder[strings.ToUpper(items[i].f.Severity)] < sevOrder[strings.ToUpper(items[j].f.Severity)]
	})

	if len(items) == 0 {
		b.pdf.SetFont("Helvetica", "I", 10)
		b.pdf.SetTextColor(22, 163, 74)
		b.pdf.CellFormat(b.bw, 8, enc(s.NoViolationsFound), "", 1, "C", false, 0, "")
		return
	}

	b.tableHeader([]colDef{
		{8, s.ColNumber, "C"},
		{22, enc(s.ColSeverity), "C"},
		{32, enc(s.ColArticle), "L"},
		{75, enc(s.ColFinding), "L"},
		{33, enc(s.ColHost), "L"},
	})

	for i, item := range items {
		fR, fG, fB := rowBG(i%2 == 1)
		sev := strings.ToUpper(item.f.Severity)
		b.tableRowColored([]colVal{
			{8, fmt.Sprintf("%d", i+1), "C", false, [3]int{100, 116, 139}},
			{22, enc(sevLabel(sev, b.lang)), "C", true, sevRGB(sev)},
			{32, enc(item.articleRef), "L", false, [3]int{30, 58, 138}},
			{75, enc(trunc(item.f.Title, 52)), "L", false, [3]int{30, 30, 30}},
			{33, enc(trunc(item.host, 22)), "L", false, [3]int{71, 85, 105}},
		}, 6.0, fR, fG, fB)
	}
	b.ln(5)

	b.h2(s.H2RemTimeline)
	for _, row := range s.TimelineRows {
		b.checkBreak(9)
		b.pdf.SetFont("Helvetica", "B", 9)
		b.pdf.SetTextColor(30, 30, 30)
		b.pdf.SetX(b.lm)
		b.pdf.CellFormat(38, 6.5, enc(row[0]), "", 0, "L", false, 0, "")
		b.pdf.SetFont("Helvetica", "", 9)
		b.pdf.SetTextColor(71, 85, 105)
		b.pdf.MultiCell(b.bw-38, 6.5, enc(row[1]), "", "L", false)
	}
}

// sevLabel returns the localised severity display string.
func sevLabel(sev, lang string) string {
	if lang != "de" {
		return sev
	}
	switch sev {
	case "CRITICAL":
		return "KRITISCH"
	case "HIGH":
		return "HOCH"
	case "MEDIUM":
		return "MITTEL"
	case "LOW":
		return "NIEDRIG"
	case "INFO":
		return "INFO"
	default:
		return sev
	}
}
