package report

import (
	"fmt"
	"strings"

	"idenaro/internal/nis2"
)

// ─── Finding card ─────────────────────────────────────────────────────────────

func (b *pb) findingCard(host string, f pdfFinding, showRecommendation bool) {
	pdf := b.pdf
	s := b.s
	sev := strings.ToUpper(f.Severity)
	sevColor := sevRGB(sev)

	descLines := pdf.SplitLines([]byte(enc(f.Description)), b.bw-11)
	descH := float64(len(descLines)) * 5.0
	recLines := 0
	if showRecommendation && f.Recommendation != "" {
		recLines = len(pdf.SplitLines([]byte(enc(f.Recommendation)), b.bw-16))
	}
	cardH := 6.5 + 5.5 + descH + float64(recLines)*5.0 + 4
	b.checkBreak(cardH + 3)

	y0 := pdf.GetY()

	// Severity bar (left)
	pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
	pdf.Rect(b.lm, y0, 3, cardH, "F")

	// Severity badge
	pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
	pdf.Rect(b.lm+5, y0+1, 22, 5, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 7)
	pdf.SetXY(b.lm+5, y0+1)
	pdf.CellFormat(22, 5, enc(sevLabel(sev, b.lang)), "", 0, "C", false, 0, "")

	// Title
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(15, 23, 42)
	pdf.SetXY(b.lm+30, y0+0.5)
	pdf.MultiCell(b.bw-31, 6, enc(f.Title), "", "L", false)

	// Meta line: host · module · confidence
	metaY := y0 + 7.5
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(100, 116, 139)
	pdf.SetXY(b.lm+5, metaY)
	pdf.MultiCell(b.bw-6, 5, enc(fmt.Sprintf(s.CardMetaFmt, host, f.Module, f.Confidence)), "", "L", false)

	// Description
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(30, 30, 30)
	pdf.SetX(b.lm + 5)
	pdf.MultiCell(b.bw-6, 5, enc(f.Description), "", "L", false)

	// Recommendation
	if showRecommendation && f.Recommendation != "" {
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetTextColor(22, 101, 52)
		pdf.SetX(b.lm + 5)
		pdf.CellFormat(28, 5, enc(s.CardRecommendation), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(22, 101, 52)
		pdf.MultiCell(b.bw-34, 5, enc(f.Recommendation), "", "L", false)
	}

	// NIS2 article tags
	if len(f.NIS2Articles) > 0 {
		pdf.SetFont("Helvetica", "I", 7.5)
		pdf.SetTextColor(30, 58, 138)
		pdf.SetX(b.lm + 5)
		refs := make([]string, 0, len(f.NIS2Articles))
		for _, ref := range f.NIS2Articles {
			id := nis2.RefToID(ref)
			if art, ok := nis2.FindByID(id); ok {
				refs = append(refs, art.Number)
			}
		}
		if len(refs) > 0 {
			pdf.CellFormat(b.bw-6, 5,
				enc(s.CardNIS2Prefix+strings.Join(refs, "  |  ")),
				"", 1, "L", false, 0, "")
		}
	}

	pdf.SetDrawColor(226, 232, 240)
	pdf.SetLineWidth(0.2)
	pdf.Line(b.lm, pdf.GetY()+0.5, b.lm+b.bw, pdf.GetY()+0.5)
	pdf.Ln(3)
}

// ─── Section / heading helpers ────────────────────────────────────────────────

func (b *pb) newSection(title string) {
	b.section++
	b.newPage()
	b.sectionBanner(fmt.Sprintf("%d. %s", b.section, enc(title)))
}

func (b *pb) sectionBanner(title string) {
	pdf := b.pdf
	y := pdf.GetY()
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(b.lm, y, b.bw, 12, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetXY(b.lm+4, y+2.5)
	pdf.CellFormat(b.bw-4, 8, title, "", 1, "L", false, 0, "")
	pdf.Ln(5)
}

func (b *pb) h2(title string) {
	b.checkBreak(14)
	pdf := b.pdf
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(30, 58, 138)
	pdf.SetX(b.lm)
	pdf.CellFormat(b.bw, 7, enc(title), "", 1, "L", false, 0, "")
	pdf.SetDrawColor(30, 58, 138)
	pdf.SetLineWidth(0.4)
	pdf.Line(b.lm, pdf.GetY(), b.lm+b.bw, pdf.GetY())
	pdf.Ln(3)
}

func (b *pb) h3(title string) {
	b.checkBreak(10)
	pdf := b.pdf
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(51, 65, 85)
	pdf.SetX(b.lm)
	pdf.CellFormat(b.bw, 6.5, enc(title), "", 1, "L", false, 0, "")
	pdf.Ln(1)
}

func (b *pb) bodyText(text string) {
	b.pdf.SetFont("Helvetica", "", 10)
	b.pdf.SetTextColor(30, 30, 30)
	b.pdf.SetX(b.lm)
	b.pdf.MultiCell(b.bw, 5.5, text, "", "L", false)
}

func (b *pb) bulletLine(text string) {
	b.checkBreak(7)
	pdf := b.pdf
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(30, 30, 30)
	y := pdf.GetY() + 2.5
	pdf.SetFillColor(30, 58, 138)
	pdf.Rect(b.lm+2, y, 2, 2, "F")
	pdf.SetXY(b.lm+7, pdf.GetY())
	pdf.MultiCell(b.bw-7, 5.5, text, "", "L", false)
}

func (b *pb) ln(h float64)    { b.pdf.Ln(h) }
func (b *pb) newPage()        { b.pdf.AddPage() }

func (b *pb) checkBreak(needed float64) {
	if b.pdf.GetY()+needed > 297-22 {
		b.pdf.AddPage()
	}
}

// ─── Table helpers ────────────────────────────────────────────────────────────

type colDef struct {
	W     float64
	Title string
	Align string
}

type colVal struct {
	W     float64
	Text  string
	Align string
	Bold  bool
	Color [3]int
}

func (b *pb) tableHeader(cols []colDef) {
	pdf := b.pdf
	b.checkBreak(10)
	pdf.SetFillColor(51, 65, 85)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetDrawColor(51, 65, 85)
	pdf.SetX(b.lm)
	for _, c := range cols {
		pdf.CellFormat(c.W, 7, enc(c.Title), "1", 0, c.Align, true, 0, "")
	}
	pdf.Ln(-1)
}

func (b *pb) tableRowColored(cols []colVal, lineH float64, fR, fG, fB int) {
	pdf := b.pdf

	maxH := lineH
	for _, c := range cols {
		style := ""
		if c.Bold {
			style = "B"
		}
		pdf.SetFont("Helvetica", style, 9)
		lines := pdf.SplitLines([]byte(c.Text), c.W-2)
		if h := float64(len(lines)) * lineH; h > maxH {
			maxH = h
		}
	}

	b.checkBreak(maxH)
	y0 := pdf.GetY()
	pdf.SetAutoPageBreak(false, 0)

	x := b.lm
	for _, c := range cols {
		style := ""
		if c.Bold {
			style = "B"
		}
		pdf.SetFont("Helvetica", style, 9)
		pdf.SetTextColor(c.Color[0], c.Color[1], c.Color[2])
		pdf.SetFillColor(fR, fG, fB)
		pdf.SetDrawColor(209, 213, 219)
		pdf.SetXY(x, y0)
		pdf.MultiCell(c.W, lineH, c.Text, "1", c.Align, true)
		x += c.W
	}
	pdf.SetXY(b.lm, y0+maxH)
	pdf.SetAutoPageBreak(true, 22)
}

// tableGroupHeader renders a full-width group label row inside a table,
// visually separating rows from different source groups (e.g. IdP vs client).
func (b *pb) tableGroupHeader(label string, totalW float64) {
	pdf := b.pdf
	b.checkBreak(7)
	pdf.SetFillColor(226, 232, 240)
	pdf.SetTextColor(30, 58, 138)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetX(b.lm)
	pdf.CellFormat(totalW, 6, "  "+label, "1", 1, "L", true, 0, "")
}
