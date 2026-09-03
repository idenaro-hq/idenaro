package report

import "fmt"

// ─── Section 3: Per-article compliance analysis ───────────────────────────────

func (b *pb) articleSections(arts []articleReport) {
	b.section++
	b.newPage()
	b.sectionBanner(fmt.Sprintf(enc(b.s.SecArticleAnalysis), b.section))

	b.pdf.SetFont("Helvetica", "", 10)
	b.pdf.SetTextColor(71, 85, 105)
	b.pdf.MultiCell(b.bw, 5.5, enc(b.s.ArticleIntro), "", "L", false)
	b.ln(4)

	for i, ar := range arts {
		b.articleSection(i+1, ar)
	}
}

func (b *pb) articleSection(sub int, ar articleReport) {
	_ = sub
	s := b.s
	b.checkBreak(40)

	pdf := b.pdf
	y := pdf.GetY()

	// Pre-measure title to determine dynamic banner height.
	// Title sits between the 30mm article-number cell and the 43mm badge area,
	// so it has (bw - 30 - 3 - 43) = bw-76 mm of horizontal space.
	titleW := b.bw - 76
	const titleLineH = 5.5
	pdf.SetFont("Helvetica", "", 10)
	titleText := enc(ar.Art.GetTitle(b.lang))
	nLines := len(pdf.SplitLines([]byte(titleText), titleW))
	if nLines == 0 {
		nLines = 1
	}
	bannerH := float64(nLines)*titleLineH + 5.0
	if bannerH < 11 {
		bannerH = 11
	}

	// Banner background
	pdf.SetFillColor(30, 58, 138)
	pdf.Rect(b.lm, y, b.bw, bannerH, "F")

	// Article reference number (left)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetXY(b.lm+3, y+2)
	pdf.CellFormat(30, 7, enc(ar.Art.Number), "", 0, "L", false, 0, "")

	// Title - wraps within the available width
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetXY(b.lm+33, y+2)
	pdf.MultiCell(titleW, titleLineH, titleText, "", "L", false)

	// Status badge (top-right corner of banner, drawn after title so it sits on top)
	badgeX := b.lm + b.bw - 43
	pdf.SetFillColor(ar.Status.r, ar.Status.g, ar.Status.b)
	pdf.Rect(badgeX, y+2, 40, 7, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetXY(badgeX, y+2)
	pdf.CellFormat(40, 7, enc(b.statusLabel(ar.Status)), "", 0, "C", false, 0, "")

	pdf.SetY(y + bannerH + 3)

	// Directive text quote box
	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(71, 85, 105)
	pdf.SetX(b.lm)
	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(203, 213, 225)
	bY := pdf.GetY()
	quoteText := enc("\"" + ar.Art.GetDirectiveText(b.lang) + "\"")
	quoteLines := pdf.SplitLines([]byte(quoteText), b.bw-8)
	quoteH := float64(len(quoteLines))*5 + 6
	pdf.Rect(b.lm, bY, b.bw, quoteH, "FD")
	pdf.SetXY(b.lm+4, bY+3)
	pdf.MultiCell(b.bw-8, 5, quoteText, "", "L", false)
	pdf.Ln(3)

	// Context note
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(30, 30, 30)
	pdf.SetX(b.lm)
	pdf.MultiCell(b.bw, 5.5, enc(ar.Art.GetContextNote(b.lang)), "", "L", false)
	pdf.Ln(4)

	hasClient := len(ar.ClientControls)+len(ar.ClientViolations) > 0

	// IdP - controls verified
	b.h3(s.H3Controls)
	if len(ar.Controls) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(148, 163, 184)
		pdf.SetX(b.lm)
		pdf.CellFormat(b.bw, 6, enc(s.NoControls), "", 1, "L", false, 0, "")
	} else {
		for _, hf := range ar.Controls {
			b.findingCard(hf.Host, hf.F, false)
		}
	}
	pdf.Ln(3)

	// IdP - violations
	b.h3(s.H3Violations)
	if len(ar.Violations) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(22, 163, 74)
		pdf.SetX(b.lm)
		pdf.CellFormat(b.bw, 6, enc(s.NoViolations), "", 1, "L", false, 0, "")
	} else {
		for _, hf := range ar.Violations {
			b.findingCard(hf.Host, hf.F, true)
		}
	}
	pdf.Ln(4)

	// Client application sub-section
	b.clientArticleSection(ar, hasClient)
	pdf.Ln(3)

	// Obligations
	b.h3(s.H3Obligations)
	for _, ob := range ar.Art.GetObligations(b.lang) {
		b.bulletLine(enc(ob))
	}
	pdf.Ln(4)

	// Section separator
	pdf.SetDrawColor(203, 213, 225)
	pdf.SetLineWidth(0.3)
	pdf.Line(b.lm, pdf.GetY(), b.lm+b.bw, pdf.GetY())
	pdf.Ln(5)
}

// clientArticleSection renders the client-application findings block within an
// article section. It is only called when a client was scanned (hasClient true)
// or when we want to show the "not scanned" notice.
func (b *pb) clientArticleSection(ar articleReport, hasClient bool) {
	s := b.s
	pdf := b.pdf

	b.checkBreak(20)

	// Sub-banner with client status badge
	y := pdf.GetY()
	bannerH := 9.0
	pdf.SetFillColor(15, 23, 42) // darker navy to visually separate from IdP banner
	pdf.Rect(b.lm, y, b.bw, bannerH, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(b.lm+3, y+1.5)
	pdf.CellFormat(b.bw-46, bannerH-3, enc(s.H3ClientSection), "", 0, "L", false, 0, "")

	if hasClient {
		// Status badge
		badgeX := b.lm + b.bw - 43
		pdf.SetFillColor(ar.ClientStatus.r, ar.ClientStatus.g, ar.ClientStatus.b)
		pdf.Rect(badgeX, y+1.5, 40, 6, "F")
		pdf.SetFont("Helvetica", "B", 7)
		pdf.SetXY(badgeX, y+1.5)
		pdf.CellFormat(40, 6, enc(b.statusLabel(ar.ClientStatus)), "", 0, "C", false, 0, "")
	}

	pdf.SetY(y + bannerH + 3)

	if !hasClient {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(148, 163, 184)
		pdf.SetX(b.lm)
		pdf.CellFormat(b.bw, 6, enc(s.NoClientScanned), "", 1, "L", false, 0, "")
		return
	}

	// Client controls
	b.h3(s.H3ClientControls)
	if len(ar.ClientControls) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(148, 163, 184)
		pdf.SetX(b.lm)
		pdf.CellFormat(b.bw, 6, enc(s.NoClientControls), "", 1, "L", false, 0, "")
	} else {
		for _, hf := range ar.ClientControls {
			b.findingCard(hf.Host, hf.F, false)
		}
	}
	pdf.Ln(3)

	// Client violations
	b.h3(s.H3ClientViolations)
	if len(ar.ClientViolations) == 0 {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(22, 163, 74)
		pdf.SetX(b.lm)
		pdf.CellFormat(b.bw, 6, enc(s.NoClientViolations), "", 1, "L", false, 0, "")
	} else {
		for _, hf := range ar.ClientViolations {
			b.findingCard(hf.Host, hf.F, true)
		}
	}
}
