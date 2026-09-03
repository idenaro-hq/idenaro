package main

import (
	"context"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"idenaro/internal/config"
	"idenaro/internal/engine"
	"idenaro/internal/i18n"
	"idenaro/internal/modules"
	"idenaro/internal/nis2"
)

// RunScan executes the IdP scanner modules against the provided targets.
// numClientTargets should be the number of relying-party targets that will be
// scanned by a subsequent RunClientScan call so both scans share one progress bar.
// Pass 0 when no client scan follows.
func (a *App) RunScan(
	targets []string,
	activeModules []string,
	skipTLS bool,
	timeoutSec int,
	numClientTargets int,
	locale string,
) []ScanResultDTO {
	a.lastSkipTLS = skipTLS

	cfg := buildConfig(skipTLS, timeoutSec, activeModules)
	parsed, err := config.ParseTargets(targets)
	if err != nil {
		return []ScanResultDTO{{Host: "configuration error", Error: err.Error()}}
	}
	cfg.Targets = parsed

	totalModules := len(cfg.ActiveModules)
	if totalModules == 0 {
		totalModules = len(config.AllModules)
	}
	grandTotal := totalModules*len(parsed) + numClientTargets
	doneCount := 0
	cfg.OnModuleDone = func(host, moduleName string) {
		doneCount++
		runtime.EventsEmit(a.ctx, "scan:module:done", ScanProgressEvent{
			Host: host, Module: moduleName, Done: doneCount, Total: grandTotal,
		})
	}

	runtime.EventsEmit(a.ctx, "scan:started", map[string]interface{}{
		"hosts": targets, "modules": cfg.ActiveModules, "total": grandTotal,
	})

	scanCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutSec+10)*time.Second*time.Duration(len(parsed)),
	)
	defer cancel()

	mods := allModules(cfg.HTTPOptions)
	opts := []engine.Option{engine.WithPostProcess(postProcess)}
	results := engine.New(cfg, mods, opts...).Run(scanCtx)
	runtime.EventsEmit(a.ctx, "scan:complete", map[string]interface{}{"hosts": targets})
	if locale == "de" {
		tx := i18n.LoadGerman()
		for i := range results {
			results[i].Findings = i18n.ApplyToFindings(results[i].Findings, tx)
			for j := range results[i].Findings {
				if german := nis2.LookupLocalized(results[i].Findings[j].Tags, "de"); len(german) > 0 {
					results[i].Findings[j].NIS2Articles = german
				}
			}
		}
	}
	return toDTO(results)
}

// RunClientScan runs only the "client" module against relying-party targets.
// It is separate from RunScan so the UI can supply a different target URL for
// the application under test.
//
// doneOffset and grandTotal allow this scan to continue the progress bar of a
// preceding RunScan call. Pass both as 0 for a client-only scan.
func (a *App) RunClientScan(
	targets []string,
	skipTLS bool,
	timeoutSec int,
	doneOffset int,
	grandTotal int,
	locale string,
) []ScanResultDTO {
	cfg := buildConfig(skipTLS, timeoutSec, []string{"client"})
	parsed, err := config.ParseTargets(targets)
	if err != nil {
		return []ScanResultDTO{{Host: "configuration error", Error: err.Error()}}
	}
	cfg.Targets = parsed

	total := grandTotal
	if total == 0 {
		total = len(parsed)
	}
	doneCount := doneOffset
	cfg.OnModuleDone = func(host, moduleName string) {
		doneCount++
		runtime.EventsEmit(a.ctx, "scan:module:done", ScanProgressEvent{
			Host: host, Module: moduleName, Done: doneCount, Total: total,
		})
	}

	scanCtx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutSec+10)*time.Second*time.Duration(len(parsed)),
	)
	defer cancel()

	clientMod := newProClient(cfg.HTTPOptions)
	opts := []engine.Option{engine.WithPostProcess(postProcess)}
	cfg.ActiveModules = []string{clientMod.Name()}
	mods := []modules.Module{clientMod}
	results := engine.New(cfg, mods, opts...).Run(scanCtx)
	if locale == "de" {
		tx := i18n.LoadGerman()
		for i := range results {
			results[i].Findings = i18n.ApplyToFindings(results[i].Findings, tx)
			for j := range results[i].Findings {
				if german := nis2.LookupLocalized(results[i].Findings[j].Tags, "de"); len(german) > 0 {
					results[i].Findings[j].NIS2Articles = german
				}
			}
		}
	}
	return toDTO(results)
}

// CancelScan aborts an in-progress scan.
func (a *App) CancelScan() {
	if a.cancel != nil {
		a.cancel()
	}
}

// runForExport re-runs a scan without progress events, used by HTML/JSON export.
func (a *App) runForExport(targets, activeModules []string, skipTLS bool) []engine.ScanResult {
	cfg := buildConfig(skipTLS, 0, activeModules)
	parsed, err := config.ParseTargets(targets)
	if err != nil {
		return nil
	}
	cfg.Targets = parsed
	mods := allModules(cfg.HTTPOptions)
	opts := []engine.Option{engine.WithPostProcess(postProcess)}
	return engine.New(cfg, mods, opts...).Run(context.Background())
}

// buildConfig creates a scan config with timeout and module list applied.
func buildConfig(skipTLS bool, timeoutSec int, activeModules []string) config.Config {
	cfg := config.DefaultConfig()
	cfg.HTTPOptions.SkipTLSVerify = skipTLS
	if timeoutSec < 10 && timeoutSec != 0 {
		timeoutSec = 10
	}
	if timeoutSec > 120 {
		timeoutSec = 120
	}
	if timeoutSec > 0 {
		cfg.Timeout = time.Duration(timeoutSec) * time.Second
		cfg.HTTPOptions.Timeout = cfg.Timeout
	}
	if len(activeModules) > 0 {
		cfg.ActiveModules = activeModules
	}
	return cfg
}
