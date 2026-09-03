package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"idenaro/internal/config"
	"idenaro/internal/engine"
	"idenaro/internal/finding"
	"idenaro/internal/i18n"
	"idenaro/internal/modules"
	freeclient "idenaro/internal/modules/free/client"
	"idenaro/internal/modules/free/endpoints"
	"idenaro/internal/modules/free/headers"
	"idenaro/internal/modules/free/oidc"
	"idenaro/internal/modules/free/saml"
	proclient "idenaro/internal/modules/pro/client"
	"idenaro/internal/modules/pro/cookies"
	"idenaro/internal/modules/pro/cors"
	"idenaro/internal/modules/pro/csp"
	"idenaro/internal/modules/pro/enumeration"
	"idenaro/internal/modules/pro/lifecycle"
	"idenaro/internal/modules/pro/mfa"
	oidcpro "idenaro/internal/modules/pro/oidc"
	"idenaro/internal/modules/pro/products"
	"idenaro/internal/modules/pro/redirects"
	samlpro "idenaro/internal/modules/pro/saml"
	"idenaro/internal/modules/pro/scim"
	"idenaro/internal/modules/pro/tls"
	"idenaro/internal/modules/pro/tokens"
	"idenaro/internal/nis2"
	"idenaro/internal/report"
	"idenaro/internal/scoring"
	"idenaro/pkg/httpclient"
)

// proModuleNames are all module names that used to be gated behind a pro
// license. They now ship unconditionally as part of the single open-source
// binary. This list extends config.AllModules at init time so ValidateModules
// accepts them.
var proModuleNames = []string{
	"oidc-pro", "saml-pro", "tls", "cookies", "cors", "csp",
	"redirects", "tokens", "mfa", "lifecycle", "scim", "products", "enumeration", "client-pro",
}

func init() {
	// Extend AllModules so --modules flag validation accepts the formerly-pro names.
	seen := make(map[string]bool, len(config.AllModules))
	for _, n := range config.AllModules {
		seen[n] = true
	}
	for _, n := range proModuleNames {
		if !seen[n] {
			config.AllModules = append(config.AllModules, n)
		}
	}
}

// isTerminal returns true when f is connected to an interactive terminal.
func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// CLI flag variables. Each corresponds to a --flag defined in init().
var (
	flagTargetHosts  []string
	flagTargetsFile  string
	flagModuleList   string
	flagOutputFormat string
	flagOutputFile   string
	flagTimeoutSec   int
	flagSkipTLS      bool
	flagVerbose      bool
	flagRealm        string
	flagClient       string
	flagLang         string
	flagPlain        bool
)

// Version is the idenaro release version, kept in sync with the UI
// (cmd/wails/docs.go GetAppVersion) and the repo-root VERSION file.
const Version = "1.1.0"

var rootCmd = &cobra.Command{
	Use:     "idenaro",
	Short:   "idenaro - IAM misconfiguration scanner",
	Version: Version,
	Long: `idenaro scans web-facing identity and access management infrastructure
for misconfigurations without requiring credentials or elevated privileges.

Checks: OIDC, SAML, Security Headers, Exposed Endpoints, TLS, Cookies, CORS,
        CSP, Redirects, Tokens, MFA, Lifecycle, SCIM, Products, Enumeration.
Output: findings in text, JSON, or HTML format.`,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a scan against one or more targets",
	Example: `  idenaro scan --target auth.example.com
  idenaro scan --target auth.example.com --format html --output report.html
  idenaro scan --targets targets.txt --modules oidc,tls,cookies
  idenaro scan --target auth.example.com --format json | jq '.results[].findings[] | select(.severity=="HIGH")'`,
	RunE: runScanCommand,
}

var listModulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "List all available scanner modules",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Available modules:")
		all := append([]string{}, config.FreeModules...)
		all = append(all, proModuleNames...)
		for _, name := range all {
			fmt.Printf("  · %s\n", name)
		}
	},
}

func init() {
	scanCmd.Flags().StringArrayVar(&flagTargetHosts, "target", nil,
		"Target host (repeatable: --target a.com --target b.com)")
	scanCmd.Flags().StringVar(&flagTargetsFile, "targets", "",
		"Path to a file with one target per line")
	scanCmd.Flags().StringVar(&flagModuleList, "modules", "",
		"Comma-separated module names to run (default: all)")
	scanCmd.Flags().StringVar(&flagOutputFormat, "format", "text",
		"Output format: text | json | html")
	scanCmd.Flags().StringVar(&flagOutputFile, "output", "",
		"Write report to this file instead of stdout")
	scanCmd.Flags().IntVar(&flagTimeoutSec, "timeout", 30,
		"Per-module timeout in seconds")
	scanCmd.Flags().BoolVar(&flagSkipTLS, "skip-tls-verify", false,
		"Skip TLS certificate verification (use for self-signed certs in lab environments)")
	scanCmd.Flags().BoolVarP(&flagVerbose, "verbose", "v", false,
		"Print per-module progress to stderr")
	scanCmd.Flags().StringVar(&flagRealm, "realm", "",
		"Keycloak realm to probe (overrides realm extracted from target URL; default: master)")
	scanCmd.Flags().StringVar(&flagClient, "client", "",
		"Client application URL to probe with the client and client-pro modules (e.g. https://app.example.com)")
	scanCmd.Flags().StringVar(&flagLang, "lang", "en",
		"Report language: en | de")
	scanCmd.Flags().BoolVarP(&flagPlain, "plain", "p", false,
		"Disable colors and progress bar (for CI/CD pipelines)")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(listModulesCmd)
}

// allModules returns the full ordered list of modules shipped in this
// (single-tier, fully open-source) binary.
func allModules(opts httpclient.Options) []modules.Module {
	return []modules.Module{
		oidc.New(opts),
		saml.New(opts),
		headers.New(opts),
		endpoints.New(opts),
		freeclient.New(opts),
		oidcpro.New(opts),
		samlpro.New(opts),
		tls.New(opts),
		cookies.New(opts),
		cors.New(opts),
		csp.New(opts),
		redirects.New(opts),
		tokens.New(opts),
		mfa.New(opts),
		lifecycle.New(opts),
		scim.New(opts),
		products.New(opts),
		enumeration.New(opts),
		proclient.New(opts),
	}
}

// postProcess runs the full pipeline after all modules complete: score
// individual findings, apply chain-finding rules, map NIS2 articles, then
// sort by severity.
func postProcess(findings []finding.Finding) []finding.Finding {
	findings = scoring.ScoreAll(findings)
	findings = scoring.ApplyChaining(findings)
	for i := range findings {
		findings[i].NIS2Articles = nis2.Lookup(findings[i].Tags)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return finding.SeverityOrder[findings[i].Severity] > finding.SeverityOrder[findings[j].Severity]
	})
	return findings
}

func runScanCommand(cmd *cobra.Command, args []string) error {
	// interactive mode: colors + progress bar. Disabled by --plain or when
	// stderr is not a terminal (redirected, piped, CI environment).
	interactive := !flagPlain && isTerminal(os.Stderr)
	if !interactive {
		color.NoColor = true
	}

	scanConfig := config.DefaultConfig()
	scanConfig.ActiveModules = append(append([]string{}, config.FreeModules...), proModuleNames...)
	scanConfig.Verbose = flagVerbose
	scanConfig.OutputFormat = flagOutputFormat
	scanConfig.OutputFile = flagOutputFile
	scanConfig.Timeout = time.Duration(flagTimeoutSec) * time.Second
	scanConfig.HTTPOptions.SkipTLSVerify = flagSkipTLS
	scanConfig.HTTPOptions.Timeout = scanConfig.Timeout

	// Parse optional module filter.
	if flagModuleList != "" {
		requestedModules := strings.Split(flagModuleList, ",")
		for i := range requestedModules {
			requestedModules[i] = strings.TrimSpace(requestedModules[i])
		}
		if err := config.ValidateModules(requestedModules); err != nil {
			return err
		}
		scanConfig.ActiveModules = requestedModules
	}

	// Collect raw target strings from --target flags and optional file.
	var rawTargets []string
	rawTargets = append(rawTargets, flagTargetHosts...)

	if flagTargetsFile != "" {
		fileTargets, err := config.LoadTargetsFromFile(flagTargetsFile)
		if err != nil {
			return err
		}
		for _, target := range fileTargets {
			rawTargets = append(rawTargets, target.Host)
		}
	}

	if len(rawTargets) == 0 {
		return fmt.Errorf("no targets specified - use --target or --targets")
	}

	parsedTargets, err := config.ParseTargets(rawTargets)
	if err != nil {
		return err
	}
	if flagRealm != "" {
		for i := range parsedTargets {
			parsedTargets[i].Realm = flagRealm
		}
	}
	scanConfig.Targets = parsedTargets

	// When --client is set, exclude client modules from the IdP scan so they
	// run only against the client target in a dedicated second pass below.
	if flagClient != "" {
		base := scanConfig.ActiveModules
		if len(base) == 0 {
			base = append(append([]string{}, config.FreeModules...), proModuleNames...)
		}
		idpModules := make([]string, 0, len(base))
		for _, m := range base {
			if m != "client" && m != "client-pro" {
				idpModules = append(idpModules, m)
			}
		}
		scanConfig.ActiveModules = idpModules
	}

	if scanConfig.OutputFormat != "json" {
		printBanner(os.Stderr, len(scanConfig.Targets), scanConfig.ActiveModules, flagTimeoutSec, interactive)
	}

	// Wire up progress bar before engine creation so the callback is set.
	var pb *scanProgress
	if interactive && scanConfig.OutputFormat != "json" {
		// Total ticks are set after engine creation; start with 0 and resize below.
		pb = newScanProgress(os.Stderr, 0)
		scanConfig.OnModuleDone = func(host, _ string) {
			pb.Tick(host)
		}
	}

	httpOpts := scanConfig.HTTPOptions
	httpOpts.Timeout = scanConfig.Timeout
	scanEngine := engine.New(scanConfig, allModules(httpOpts), engine.WithPostProcess(postProcess))
	if scanConfig.Verbose {
		fmt.Fprintf(os.Stderr, "Active modules: %s\n", strings.Join(scanEngine.ActiveModuleNames(), ", "))
	}

	// Now we know the exact module count; rebuild the bar with the real total.
	if pb != nil {
		total := len(scanEngine.ActiveModuleNames()) * len(scanConfig.Targets)
		pb = newScanProgress(os.Stderr, total)
		scanConfig.OnModuleDone = func(host, _ string) {
			pb.Tick(host)
		}
	}

	scanStart := time.Now()
	results := scanEngine.Run(context.Background())

	// Run client modules separately against the client app target so their
	// findings appear under the client host rather than the IdP host.
	if flagClient != "" {
		clientTargets, err := config.ParseTargets([]string{flagClient})
		if err == nil && len(clientTargets) > 0 {
			clientCfg := config.DefaultConfig()
			clientCfg.ActiveModules = []string{"client-pro"}
			clientCfg.Targets = clientTargets
			clientCfg.HTTPOptions = scanConfig.HTTPOptions
			clientCfg.Timeout = scanConfig.Timeout
			clientEngine := engine.New(clientCfg, allModules(httpOpts), engine.WithPostProcess(postProcess))
			results = append(results, clientEngine.Run(context.Background())...)
		}
	}

	totalElapsed := time.Since(scanStart)

	// Clear the progress line before printing the report.
	if pb != nil {
		pb.Clear()
	}

	if flagLang == "de" {
		tx := i18n.LoadGerman()
		for i := range results {
			results[i].Findings = i18n.ApplyToFindings(results[i].Findings, tx)
		}
	}

	// Determine the output destination.
	outputWriter := os.Stdout
	if flagOutputFile != "" {
		outputFile, createErr := os.Create(flagOutputFile)
		if createErr != nil {
			return fmt.Errorf("cannot create output file: %w", createErr)
		}
		defer func() { _ = outputFile.Close() }()
		outputWriter = outputFile
	}

	// Color the text report only when writing to an interactive stdout and the
	// output is not redirected to a file.
	textColor := interactive && flagOutputFile == ""

	switch scanConfig.OutputFormat {
	case "json":
		if err := report.WriteJSON(outputWriter, results, true); err != nil {
			return err
		}
	case "html":
		if err := report.WriteHTML(outputWriter, results); err != nil {
			return err
		}
		if flagOutputFile != "" {
			fmt.Fprintf(os.Stderr, "HTML report written to: %s\n", flagOutputFile)
		}
	default:
		if err := report.WriteText(outputWriter, results, report.TextOptions{Color: textColor}); err != nil {
			return err
		}
	}

	if scanConfig.OutputFormat != "html" || flagOutputFile == "" {
		printSummary(results, totalElapsed, interactive)
	}

	return nil
}

// printBanner writes the startup header to w.
func printBanner(w *os.File, targetCount int, modules []string, timeoutSec int, _ bool) {
	dim := color.New(color.FgHiBlack)
	bold := color.New(color.FgCyan, color.Bold)
	acc := color.New(color.FgHiCyan)

	_, _ = fmt.Fprintln(w)
	_, _ = bold.Fprintln(w, "  idenaro  ·  IAM Security Scanner")
	_, _ = dim.Fprintln(w, "  ─────────────────────────────────────────────────")
	_, _ = fmt.Fprintf(w, "  %s %s   %s %s   %s %ds\n",
		dim.Sprint("targets"),
		acc.Sprint(targetCount),
		dim.Sprint("modules"),
		acc.Sprint(strings.Join(modules, ", ")),
		dim.Sprint("timeout"),
		timeoutSec,
	)
	_, _ = fmt.Fprintln(w)
}

// printSummary writes the per-host result table to stderr.
func printSummary(results []engine.ScanResult, elapsed time.Duration, colorOn bool) {
	dim := color.New(color.FgHiBlack)
	bold := color.New(color.Bold)
	sevColors := map[finding.Severity]*color.Color{
		finding.Critical: color.New(color.FgRed, color.Bold),
		finding.High:     color.New(color.FgHiRed),
		finding.Medium:   color.New(color.FgYellow),
		finding.Low:      color.New(color.FgCyan),
		finding.Info:     color.New(color.FgHiBlue),
	}

	_, _ = fmt.Fprintln(os.Stderr)
	_, _ = dim.Fprintln(os.Stderr, "  ──────────────────────────────────────────────────────────────────────────────────────────────────")
	_, _ = bold.Fprintln(os.Stderr, "  Results")
	_, _ = dim.Fprintln(os.Stderr, "  ──────────────────────────────────────────────────────────────────────────────────────────────────")

	for _, r := range results {
		if r.Error != nil {
			_, _ = color.New(color.FgRed).Fprintf(os.Stderr, "  [ERROR] %s: %v\n", r.Host, r.Error)
			continue
		}
		counts := make(map[finding.Severity]int)
		for _, f := range r.Findings {
			counts[f.Severity]++
		}

		host := fmt.Sprintf("%-40s", r.Host)
		sev := fmt.Sprintf("C:%-2d H:%-2d M:%-2d L:%-2d I:%-2d",
			counts[finding.Critical],
			counts[finding.High],
			counts[finding.Medium],
			counts[finding.Low],
			counts[finding.Info],
		)

		// Color the severity counts if any are non-zero.
		if colorOn {
			parts := []string{}
			for _, s := range []finding.Severity{finding.Critical, finding.High, finding.Medium, finding.Low, finding.Info} {
				label := string(s[:1])
				n := counts[s]
				formatted := fmt.Sprintf("%s:%-2d", label, n)
				if n > 0 {
					formatted = sevColors[s].Sprint(formatted)
				} else {
					formatted = dim.Sprint(formatted)
				}
				parts = append(parts, formatted)
			}
			sev = strings.Join(parts, "  ")
		}

		score := fmt.Sprintf("score:%-3d", r.OverallScore)
		dur := dim.Sprintf("(%s)", r.Duration.Round(time.Millisecond))
		fmt.Fprintf(os.Stderr, "  %s  %s  %s  %s\n", bold.Sprint(host), sev, dim.Sprint(score), dur)
	}

	_, _ = dim.Fprintln(os.Stderr, "  ──────────────────────────────────────────────────────────────────────────────────────────────────")
	fmt.Fprintf(os.Stderr, "  %s %s\n\n", dim.Sprint("completed in"), elapsed.Round(time.Millisecond))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
