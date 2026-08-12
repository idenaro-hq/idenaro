package report

import (
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/fatih/color"

	"idenaro/internal/engine"
	"idenaro/internal/finding"
)

// HTMLReportData is the root object passed to the HTML template.
type HTMLReportData struct {
	GeneratedAt   string
	Results       []HTMLHostResult
	TotalHosts    int
	TotalFindings int
	HasCritical   bool
}

// HTMLHostResult holds the display-ready values for one scanned host.
// Counts reuses JSONFindingCount because the severity breakdown is identical.
type HTMLHostResult struct {
	Host         string
	OverallScore int
	ScoreClass   string // CSS modifier: "good" | "moderate" | "atrisk" | "critical"
	Duration     string
	Findings     []finding.Finding
	Counts       JSONFindingCount
}

const htmlReportTemplate = `<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>idenaro - IAM Security Report</title>
<style>
  :root {
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #65a30d; --info: #0284c7; --bg: #0f172a; --surface: #1e293b;
    --border: #334155; --text: #e2e8f0; --muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
  h2 { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; }
  h3 { font-size: 0.9rem; font-weight: 600; }
  .meta { color: var(--muted); font-size: 0.8rem; margin-bottom: 2rem; }
  .host-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1.5rem; overflow: hidden; }
  .host-header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
  .host-name { font-weight: 600; font-size: 1rem; font-family: monospace; }
  .score-badge { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; }
  .score-good     { background: rgba(101,163,13,0.2); color: #6dd87a; border: 1px solid #6dd87a; }
  .score-moderate { background: rgba(217,119,6,0.2);  color: var(--medium); border: 1px solid var(--medium); }
  .score-atrisk   { background: rgba(234,88,12,0.2);  color: var(--high);   border: 1px solid var(--high); }
  .score-critical { background: rgba(220,38,38,0.2);  color: var(--critical); border: 1px solid var(--critical); }
  .count-bar { display: flex; gap: 0.5rem; padding: 0.5rem 1.5rem; background: rgba(0,0,0,0.2); }
  .count-item { font-size: 0.78rem; }
  .finding { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
  .finding:last-child { border-bottom: none; }
  .finding-header { display: flex; align-items: flex-start; gap: 0.75rem; margin-bottom: 0.5rem; }
  .severity-badge { flex-shrink: 0; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
  .sev-CRITICAL { background: rgba(220,38,38,0.2); color: var(--critical); border: 1px solid var(--critical); }
  .sev-HIGH     { background: rgba(234,88,12,0.2); color: var(--high);     border: 1px solid var(--high); }
  .sev-MEDIUM   { background: rgba(217,119,6,0.2); color: var(--medium);   border: 1px solid var(--medium); }
  .sev-LOW      { background: rgba(101,163,13,0.2);color: var(--low);      border: 1px solid var(--low); }
  .sev-INFO     { background: rgba(2,132,199,0.2); color: var(--info);     border: 1px solid var(--info); }
  .finding-title { font-weight: 600; font-size: 0.9rem; }
  .finding-meta  { font-size: 0.75rem; color: var(--muted); margin-top: 0.15rem; }
  .finding-desc  { color: var(--muted); font-size: 0.83rem; margin-bottom: 0.5rem; line-height: 1.5; }
  .section-label { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin-bottom: 0.2rem; }
  .section-block { margin-top: 0.5rem; }
  .evidence-item { font-family: monospace; font-size: 0.78rem; background: rgba(0,0,0,0.3); padding: 0.25rem 0.5rem; border-radius: 4px; margin-bottom: 0.2rem; word-break: break-all; }
  .recommendation-text { font-size: 0.83rem; color: #86efac; }
  .nis2-tag-list { display: flex; flex-wrap: wrap; gap: 0.3rem; margin-top: 0.4rem; }
  .nis2-tag { background: rgba(99,102,241,0.15); border: 1px solid rgba(99,102,241,0.4); color: #a5b4fc; font-size: 0.7rem; padding: 0.15rem 0.4rem; border-radius: 4px; }
  .no-findings { padding: 1.5rem; color: var(--muted); text-align: center; font-size: 0.85rem; }
</style>
</head>
<body>
<h1>🔐 idenaro - IAM Security Report</h1>
<p class="meta">Generated: {{.GeneratedAt}} · {{.TotalHosts}} host(s) scanned · {{.TotalFindings}} finding(s)</p>

{{range .Results}}
<div class="host-card">
  <div class="host-header">
    <span class="host-name">{{.Host}}</span>
    <div style="display:flex;align-items:center;gap:0.75rem;">
      <span style="font-size:0.78rem;color:#94a3b8;">{{.Duration}}</span>
      <span class="score-badge score-{{.ScoreClass}}">Risk Score: {{.OverallScore}}</span>
    </div>
  </div>
  <div class="count-bar">
    <span class="count-item" style="color:var(--critical)">CRITICAL: {{.Counts.Critical}}</span>
    <span class="count-item" style="color:var(--high)">HIGH: {{.Counts.High}}</span>
    <span class="count-item" style="color:var(--medium)">MEDIUM: {{.Counts.Medium}}</span>
    <span class="count-item" style="color:var(--low)">LOW: {{.Counts.Low}}</span>
    <span class="count-item" style="color:var(--info)">INFO: {{.Counts.Info}}</span>
  </div>
  {{if .Findings}}
    {{range .Findings}}
    <div class="finding">
      <div class="finding-header">
        <span class="severity-badge sev-{{.Severity}}">{{.Severity}}</span>
        <div>
          <div class="finding-title">{{.Title}}</div>
          <div class="finding-meta">Risk: {{.RiskScore}} · Module: {{.Module}} · Confidence: {{.Confidence}}</div>
        </div>
      </div>
      <div class="finding-desc">{{.Description}}</div>
      {{if .Evidence}}
      <div class="section-block">
        <div class="section-label">Evidence</div>
        {{range .Evidence}}<div class="evidence-item">{{.}}</div>{{end}}
      </div>
      {{end}}
      {{if .Recommendation}}
      <div class="section-block">
        <div class="section-label">Recommendation</div>
        <div class="recommendation-text">{{.Recommendation}}</div>
      </div>
      {{end}}
      {{if .NIS2Articles}}
      <div class="section-block">
        <div class="section-label">NIS2 Mapping</div>
        <div class="nis2-tag-list">
          {{range .NIS2Articles}}<span class="nis2-tag">{{.}}</span>{{end}}
        </div>
      </div>
      {{end}}
    </div>
    {{end}}
  {{else}}
  <div class="no-findings">✓ No findings for this host</div>
  {{end}}
</div>
{{end}}
</body>
</html>`

// WriteHTML renders all scan results as a self-contained HTML report and
// writes it to w. The report includes inline CSS and requires no external
// resources, making it suitable for offline delivery to clients.
func WriteHTML(w io.Writer, results []engine.ScanResult) error {
	reportTemplate, err := template.New("report").Parse(htmlReportTemplate)
	if err != nil {
		return fmt.Errorf("report: template parse error: %w", err)
	}
	templateData := buildHTMLReportData(results)
	return reportTemplate.Execute(w, templateData)
}

func buildHTMLReportData(results []engine.ScanResult) HTMLReportData {
	reportData := HTMLReportData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		TotalHosts:  len(results),
	}

	for _, scanResult := range results {
		hostCounts := countFindingsBySeverity(scanResult.Findings)
		reportData.TotalFindings += hostCounts.Total
		if hostCounts.Critical > 0 {
			reportData.HasCritical = true
		}
		reportData.Results = append(reportData.Results, HTMLHostResult{
			Host:         scanResult.Host,
			OverallScore: scanResult.OverallScore,
			ScoreClass:   riskScoreToCSS(scanResult.OverallScore),
			Duration:     scanResult.Duration.Round(time.Millisecond).String(),
			Findings:     scanResult.Findings,
			Counts:       hostCounts,
		})
	}

	return reportData
}

// riskScoreToCSS maps a 0-100 risk score to a CSS class name.
// Higher score = higher risk = warmer colour.
func riskScoreToCSS(riskScore int) string {
	switch {
	case riskScore >= 75:
		return "critical"
	case riskScore >= 50:
		return "atrisk"
	case riskScore >= 25:
		return "moderate"
	default:
		return "good"
	}
}

// TextOptions controls optional rendering behaviours for the plain-text report.
type TextOptions struct {
	// Color enables ANSI colour codes. Set only when writing to an interactive
	// terminal; it produces garbage in file output or CI logs.
	Color bool
}

var (
	clrCritical   = color.New(color.FgRed, color.Bold)
	clrHigh       = color.New(color.FgHiRed)
	clrMedium     = color.New(color.FgYellow)
	clrLow        = color.New(color.FgCyan)
	clrInfo       = color.New(color.FgHiBlue)
	clrBold       = color.New(color.Bold)
	clrDim        = color.New(color.FgHiBlack)
	clrGreen      = color.New(color.FgHiGreen)
	clrEvidence   = color.New(color.FgHiBlue)
	clrHostHeader = color.New(color.FgHiCyan, color.Bold)
)

func severityPrinter(sev finding.Severity) *color.Color {
	switch sev {
	case finding.Critical:
		return clrCritical
	case finding.High:
		return clrHigh
	case finding.Medium:
		return clrMedium
	case finding.Low:
		return clrLow
	default:
		return clrInfo
	}
}

// WriteText writes a plain-text scan report to w, suitable for terminal
// output. Summary lines go to stderr in the CLI; this writes the findings.
// Pass TextOptions{Color: true} when writing to an interactive terminal.
func WriteText(w io.Writer, results []engine.ScanResult, opts TextOptions) error {
	if !opts.Color {
		color.NoColor = true
	}

	sep := clrDim.Sprint(strings.Repeat("─", 55))

	if _, err := clrBold.Fprintln(w, "\n  Findings"); err != nil {
		return err
	}
	if _, err := clrDim.Fprintf(w, "  Generated: %s\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")); err != nil {
		return err
	}

	for _, scanResult := range results {
		if _, err := fmt.Fprintln(w); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, sep); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "  %s  %s  %s\n",
			clrHostHeader.Sprint(scanResult.Host),
			clrDim.Sprintf("score:%d", scanResult.OverallScore),
			clrDim.Sprintf("(%s)", scanResult.Duration.Round(time.Millisecond)),
		); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, sep); err != nil {
			return err
		}

		if len(scanResult.Findings) == 0 {
			if _, err := clrGreen.Fprintln(w, "  ✓  No findings"); err != nil {
				return err
			}
			continue
		}

		for _, f := range scanResult.Findings {
			sev := severityPrinter(f.Severity)
			badge := sev.Sprintf("  %-10s", "["+string(f.Severity)+"]")
			title := clrBold.Sprint(f.Title)
			if _, err := fmt.Fprintf(w, "%s %s\n", badge, title); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(w, "  %s  %s\n", strings.Repeat(" ", 10), clrDim.Sprint(f.Description)); err != nil {
				return err
			}
			if len(f.Evidence) > 0 {
				if _, err := fmt.Fprintf(w, "  %s  %s\n", strings.Repeat(" ", 10), clrEvidence.Sprint("Evidence:")); err != nil {
					return err
				}
				for _, evidenceLine := range f.Evidence {
					if _, err := fmt.Fprintf(w, "  %s  %s\n", strings.Repeat(" ", 10), clrEvidence.Sprint("· "+evidenceLine)); err != nil {
						return err
					}
				}
			}
			if _, err := fmt.Fprintf(w, "  %s  %s\n", strings.Repeat(" ", 10), clrGreen.Sprint("→ "+f.Recommendation)); err != nil {
				return err
			}
			if len(f.NIS2Articles) > 0 {
				if _, err := fmt.Fprintf(w, "  %s  %s %s\n", strings.Repeat(" ", 10), clrDim.Sprint("NIS2:"), strings.Join(f.NIS2Articles, ", ")); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
	}
	return nil
}
