package engine

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"idenaro/internal/config"
	"idenaro/internal/finding"
	"idenaro/internal/modules"
	"idenaro/internal/scoring"
)

// maxConcurrentTargets is the maximum number of targets scanned in parallel.
const maxConcurrentTargets = 5

// ScanResult holds the complete output for a single scanned host.
type ScanResult struct {
	Host         string
	Findings     []finding.Finding
	OverallScore int
	Duration     time.Duration
	Error        error
}

// PostProcessFn is applied to all collected findings after every module has run.
// The default applies basic risk scoring and sorts by severity.
// The pro binary injects NIS2 mapping and chain scoring via WithPostProcess.
type PostProcessFn func([]finding.Finding) []finding.Finding

// Option is a functional option for Engine.
type Option func(*Engine)

// WithPostProcess replaces the default post-processing pipeline.
func WithPostProcess(fn PostProcessFn) Option {
	return func(e *Engine) { e.postProcess = fn }
}

// Engine orchestrates module execution across one or more targets.
type Engine struct {
	cfg            config.Config
	activeModules  []modules.Module
	verboseLogging bool
	postProcess    PostProcessFn
}

// New initialises an Engine from the given config and the caller-supplied module
// list. Only modules whose Name() appears in cfg.ActiveModules are loaded; if
// cfg.ActiveModules is empty, all availableModules are used.
func New(cfg config.Config, availableModules []modules.Module, opts ...Option) *Engine {
	e := &Engine{
		cfg:            cfg,
		verboseLogging: cfg.Verbose,
		postProcess:    defaultPostProcess,
	}
	for _, opt := range opts {
		opt(e)
	}
	e.activeModules = filterModules(availableModules, cfg.ActiveModules)
	return e
}

func defaultPostProcess(findings []finding.Finding) []finding.Finding {
	findings = scoring.ScoreAll(findings)
	sortFindingsBySeverity(findings)
	return findings
}

func filterModules(available []modules.Module, activeNames []string) []modules.Module {
	if len(activeNames) == 0 {
		return available
	}
	enabled := make(map[string]bool, len(activeNames))
	for _, name := range activeNames {
		enabled[name] = true
	}
	filtered := make([]modules.Module, 0, len(available))
	for _, mod := range available {
		if enabled[mod.Name()] {
			filtered = append(filtered, mod)
		}
	}
	return filtered
}

// Run executes all active modules against every target in the config.
// Up to maxConcurrentTargets targets are scanned in parallel; results are
// returned in the same order as the targets slice.
func (e *Engine) Run(ctx context.Context) []ScanResult {
	results := make([]ScanResult, len(e.cfg.Targets))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrentTargets)

	for targetIndex, target := range e.cfg.Targets {
		wg.Add(1)
		go func(idx int, t modules.Target) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[idx] = e.scanSingleTarget(ctx, t)
		}(targetIndex, target)
	}

	wg.Wait()
	return results
}

// moduleOutput captures the findings and error returned by a single module run.
type moduleOutput struct {
	moduleName string
	findings   []finding.Finding
	err        error
}

// scanSingleTarget runs all active modules against one target concurrently,
// then runs the post-processing pipeline before returning the complete result.
func (e *Engine) scanSingleTarget(ctx context.Context, target modules.Target) ScanResult {
	scanStart := time.Now()

	outputChannel := make(chan moduleOutput, len(e.activeModules))

	var wg sync.WaitGroup
	for _, mod := range e.activeModules {
		wg.Add(1)
		go func(m modules.Module) {
			defer wg.Done()

			moduleCtx, cancelModuleCtx := context.WithTimeout(ctx, e.cfg.Timeout)
			defer cancelModuleCtx()

			if e.verboseLogging {
				log.Printf("[%s] starting module: %s", target.Host, m.Name())
			}

			moduleFindings, runErr := m.Run(moduleCtx, target)
			outputChannel <- moduleOutput{
				moduleName: m.Name(),
				findings:   moduleFindings,
				err:        runErr,
			}
		}(mod)
	}

	go func() {
		wg.Wait()
		close(outputChannel)
	}()

	var collectedFindings []finding.Finding
	for output := range outputChannel {
		if output.err != nil {
			if e.verboseLogging {
				log.Printf("[%s] module %s error: %v", target.Host, output.moduleName, output.err)
			}
		} else {
			collectedFindings = append(collectedFindings, output.findings...)
		}

		if e.cfg.OnModuleDone != nil {
			e.cfg.OnModuleDone(target.Host, output.moduleName)
		}
	}

	collectedFindings = e.postProcess(collectedFindings)

	return ScanResult{
		Host:         target.Host,
		Findings:     collectedFindings,
		OverallScore: scoring.OverallScore(collectedFindings),
		Duration:     time.Since(scanStart),
	}
}

// sortFindingsBySeverity sorts the slice in-place from most to least severe.
func sortFindingsBySeverity(findings []finding.Finding) {
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && findings[j].Weight() > findings[j-1].Weight(); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
}

// ActiveModuleNames returns the names of the loaded modules in load order.
func (e *Engine) ActiveModuleNames() []string {
	names := make([]string, len(e.activeModules))
	for i, mod := range e.activeModules {
		names[i] = mod.Name()
	}
	return names
}

// PrintSummary writes a one-line human-readable summary per host to stdout.
func PrintSummary(results []ScanResult) {
	for _, result := range results {
		if result.Error != nil {
			fmt.Printf("  [ERROR] %s: %v\n", result.Host, result.Error)
			continue
		}

		countsBySeverity := make(map[finding.Severity]int)
		for _, f := range result.Findings {
			countsBySeverity[f.Severity]++
		}

		fmt.Printf("  %-40s  score=%-3d  C=%-2d H=%-2d M=%-2d L=%-2d I=%-2d  (%s)\n",
			result.Host, result.OverallScore,
			countsBySeverity[finding.Critical],
			countsBySeverity[finding.High],
			countsBySeverity[finding.Medium],
			countsBySeverity[finding.Low],
			countsBySeverity[finding.Info],
			result.Duration.Round(time.Millisecond),
		)
	}
}
