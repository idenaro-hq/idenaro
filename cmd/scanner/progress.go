package main

import (
	"io"

	"github.com/schollz/progressbar/v3"
)

// scanProgress wraps progressbar for concurrent use during scanning.
type scanProgress struct {
	bar *progressbar.ProgressBar
}

func newScanProgress(w io.Writer, total int) *scanProgress {
	bar := progressbar.NewOptions(total,
		progressbar.OptionSetWriter(w),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(30),
		progressbar.OptionSetDescription("[cyan]  scanning[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]━[reset]",
			SaucerHead:    "[green]╸[reset]",
			SaucerPadding: "─",
			BarStart:      " [",
			BarEnd:        "]",
		}),
		progressbar.OptionShowDescriptionAtLineEnd(),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionSetRenderBlankState(true),
	)
	return &scanProgress{bar: bar}
}

func (p *scanProgress) Tick(host string) {
	p.bar.Describe("[cyan]  " + host + "[reset]")
	_ = p.bar.Add(1)
}

func (p *scanProgress) Clear() {
	_ = p.bar.Clear()
}
