package report

import "fmt"

// ─── Section 1: Executive Summary ─────────────────────────────────────────────

func (b *pb) execSummary(results []pdfScanResult, arts []articleReport) {
	s := b.s
	b.newSection(s.SecExecSummary)

	b.h2(s.H2OverallRisk)
	b.bodyText(enc(s.BodyOverallRisk))
	b.ln(3)

	cols := []colDef{
		{70, enc(s.ColSystem), "L"},
		{25, enc(s.ColRiskScore), "C"},
		{25, enc(s.ColCritical), "C"},
		{25, enc(s.ColHigh), "C"},
		{25, enc(s.ColMedium), "C"},
	}

	var idpResults, clientResults []pdfScanResult
	for _, r := range results {
		if isClientResult(r) {
			clientResults = append(clientResults, r)
		} else {
			idpResults = append(idpResults, r)
		}
	}

	renderRiskRows := func(rows []pdfScanResult, alt bool) bool {
		for _, r := range rows {
			fR, fG, fB := rowBG(alt)
			scoreStr := fmt.Sprintf("%d / 100", r.Score)
			var scoreColor [3]int
			switch {
			case r.Score >= 70:
				scoreColor = [3]int{220, 38, 38}
			case r.Score >= 40:
				scoreColor = [3]int{217, 119, 6}
			default:
				scoreColor = [3]int{22, 163, 74}
			}
			b.tableRowColored([]colVal{
				{70, enc(r.Host), "L", false, [3]int{30, 30, 30}},
				{25, scoreStr, "C", true, scoreColor},
				{25, fmt.Sprintf("%d", r.Counts.Critical), "C", false, critColor(r.Counts.Critical)},
				{25, fmt.Sprintf("%d", r.Counts.High), "C", false, highColor(r.Counts.High)},
				{25, fmt.Sprintf("%d", r.Counts.Medium), "C", false, medColor(r.Counts.Medium)},
			}, 6.0, fR, fG, fB)
			alt = !alt
		}
		return alt
	}

	b.tableHeader(cols)
	// IdP group header
	b.tableGroupHeader(enc(s.LabelIdpSystems), 170)
	alt := renderRiskRows(idpResults, false)

	if len(clientResults) > 0 {
		b.tableGroupHeader(enc(s.LabelClientSystems), 170)
		renderRiskRows(clientResults, alt)
	}
	b.ln(6)

	b.h2(s.H2ComplianceMatrix)
	b.bodyText(enc(s.BodyComplianceMatrix))
	b.ln(3)

	b.tableHeader([]colDef{
		{30, enc(s.ColArticle), "L"},
		{72, enc(s.ColTitle), "L"},
		{40, enc(s.ColStatus), "C"},
		{15, enc(s.ColControls), "C"},
		{13, enc(s.ColIssues), "C"},
	})
	alt = false
	for _, ar := range arts {
		fR, fG, fB := rowBG(alt)
		allControls := len(ar.Controls) + len(ar.ClientControls)
		allViolations := append(ar.Violations, ar.ClientViolations...)
		b.tableRowColored([]colVal{
			{30, enc(ar.Art.Number), "L", false, [3]int{30, 58, 138}},
			{72, enc(trunc(ar.Art.GetTitle(b.lang), 55)), "L", false, [3]int{30, 30, 30}},
			{40, enc(b.statusLabel(ar.Status)), "C", true, [3]int{ar.Status.r, ar.Status.g, ar.Status.b}},
			{15, fmt.Sprintf("%d", allControls), "C", false, [3]int{22, 163, 74}},
			{13, fmt.Sprintf("%d", len(allViolations)), "C", false, issueSeverityColor(allViolations)},
		}, 6.0, fR, fG, fB)
		alt = !alt
	}
	b.ln(6)

	b.h2(s.H2StatusDefs)
	statuses := []compStatus{csCompliant, csLargelyCompliant, csRequiresAttention, csNonCompliant, csNotAssessed}
	for i, row := range s.LegendRows {
		b.checkBreak(8)
		b.pdf.SetFillColor(255, 255, 255)
		b.pdf.SetDrawColor(226, 232, 240)
		x, y := b.pdf.GetX(), b.pdf.GetY()
		b.pdf.SetFillColor(statuses[i].r, statuses[i].g, statuses[i].b)
		b.pdf.Rect(b.lm, y+1.5, 3, 3.5, "F")
		b.pdf.SetFont("Helvetica", "B", 8)
		b.pdf.SetTextColor(statuses[i].r, statuses[i].g, statuses[i].b)
		b.pdf.SetXY(x+5, y)
		b.pdf.CellFormat(40, 6, enc(row[0]), "", 0, "L", false, 0, "")
		b.pdf.SetFont("Helvetica", "", 8)
		b.pdf.SetTextColor(71, 85, 105)
		b.pdf.CellFormat(125, 6, enc(row[1]), "", 1, "L", false, 0, "")
	}
}

// ─── Section 2: Scope and Methodology ────────────────────────────────────────

func (b *pb) scopeSection(results []pdfScanResult) {
	s := b.s
	b.newSection(s.SecScope)

	b.h2(s.H2SystemsInScope)
	b.bodyText(enc(s.BodySystemsInScope))
	b.ln(2)

	var scopeIdp, scopeClient []pdfScanResult
	for _, r := range results {
		if isClientResult(r) {
			scopeClient = append(scopeClient, r)
		} else {
			scopeIdp = append(scopeIdp, r)
		}
	}

	b.h3(s.LabelIdpSystems)
	for _, r := range scopeIdp {
		b.bulletLine(enc(fmt.Sprintf("%s   (score: %d/100, %s)", r.Host, r.Score, r.Duration)))
	}
	if len(scopeClient) > 0 {
		b.ln(2)
		b.h3(s.LabelClientSystems)
		for _, r := range scopeClient {
			b.bulletLine(enc(fmt.Sprintf("%s   (score: %d/100, %s)", r.Host, r.Score, r.Duration)))
		}
	}
	b.ln(5)

	b.h2(s.H2Methodology)
	b.bodyText(enc(s.BodyMethodology1))
	b.ln(3)
	b.bodyText(enc(s.BodyMethodology2))
	b.ln(1)
	for _, a := range s.Activities {
		b.bulletLine(enc(a))
	}
	b.ln(5)

	b.h2(s.H2Limitations)
	for _, l := range s.Limitations {
		b.bulletLine(enc(l))
	}
	b.ln(5)

	b.h2(s.H2ComplianceBasis)
	b.bodyText(enc(s.BodyComplianceBasis))
}

// rowBG returns alternating row background colours.
func rowBG(alt bool) (int, int, int) {
	if alt {
		return 241, 245, 249
	}
	return 255, 255, 255
}
