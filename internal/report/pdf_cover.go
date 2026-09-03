package report

import "fmt"

func (b *pb) cover(results []pdfScanResult) {
	pdf := b.pdf
	s := b.s
	pdf.AddPage()

	// Top banner
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(0, 0, 210, 22, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.SetXY(20, 7)
	pdf.CellFormat(90, 8, "Idenaro", "", 0, "L", false, 0, "")
	pdf.SetFont("Helvetica", "", 9)
	pdf.CellFormat(80, 8, enc(s.CoverPlatform), "", 1, "R", false, 0, "")

	// Main title block
	pdf.SetTextColor(15, 23, 42)
	pdf.SetFont("Helvetica", "B", 30)
	pdf.SetY(55)
	pdf.CellFormat(170, 14, "NIS2 Compliance", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "B", 22)
	pdf.CellFormat(170, 11, enc(s.CoverReportSub), "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(71, 85, 105)
	pdf.SetY(pdf.GetY() + 3)
	pdf.CellFormat(170, 7, enc(s.CoverDirective), "", 1, "C", false, 0, "")

	// Divider
	pdf.SetDrawColor(30, 58, 138)
	pdf.SetLineWidth(0.6)
	pdf.Line(20, pdf.GetY()+5, 190, pdf.GetY()+5)
	pdf.Ln(12)

	// Metadata box
	pdf.SetFillColor(248, 250, 252)
	pdf.SetDrawColor(226, 232, 240)
	pdf.SetLineWidth(0.3)
	metaY := pdf.GetY()
	pdf.Rect(20, metaY, 170, 52, "FD")

	col1W, col2W := 48.0, 120.0
	rowH := 7.5
	metaRows := [][2]string{
		{s.CoverMetaDate, b.scanDate},
		{s.CoverMetaScanner, s.CoverMetaScannerV},
		{s.CoverMetaType, s.CoverMetaTypeV},
		{s.CoverMetaMethod, s.CoverMetaMethodV},
		{s.CoverMetaScope, fmt.Sprintf(s.CoverMetaScopeV, len(results))},
		{s.CoverMetaClass, s.CoverMetaClassV},
	}
	pdf.SetXY(25, metaY+4)
	for _, row := range metaRows {
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(30, 58, 138)
		pdf.CellFormat(col1W, rowH, enc(row[0]), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(30, 30, 30)
		pdf.CellFormat(col2W, rowH, enc(row[1]), "", 1, "L", false, 0, "")
		pdf.SetX(25)
	}
	pdf.SetY(metaY + 58)

	// Assessed targets
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(15, 23, 42)
	pdf.CellFormat(170, 7, enc(s.CoverSystems), "", 1, "L", false, 0, "")
	pdf.SetDrawColor(30, 58, 138)
	pdf.SetLineWidth(0.4)
	lY := pdf.GetY() + 1
	pdf.Line(20, lY, 190, lY)
	pdf.Ln(5)

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(30, 30, 30)
	for _, r := range results {
		pdf.SetX(25)
		pdf.SetFillColor(30, 58, 138)
		bY := pdf.GetY() + 2.5
		pdf.Rect(21, bY, 2, 2, "F")
		pdf.CellFormat(160, 7, enc(r.Host), "", 1, "L", false, 0, "")
	}

	// Confidentiality notice at bottom
	pdf.SetY(246)
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(20, pdf.GetY(), 170, 40, "F")
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetXY(25, pdf.GetY()+5)
	pdf.CellFormat(160, 6, enc(s.CoverConfTitle), "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(25, pdf.GetY()+1)
	pdf.MultiCell(160, 5, enc(s.CoverConfBody), "", "C", false)
}
