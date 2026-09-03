package main

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"idenaro/internal/i18n"
	"idenaro/internal/report"
)

// ExportHTML re-runs the scan for the given targets and returns an HTML report
// as a string. Respects the TLS setting from the last RunScan call.
func (a *App) ExportHTML(targets []string, activeModules []string) string {
	results := a.runForExport(targets, activeModules, a.lastSkipTLS)
	if results == nil {
		return ""
	}
	var buf bytes.Buffer
	if err := report.WriteHTML(&buf, results); err != nil {
		return fmt.Sprintf("<!-- report error: %v -->", err)
	}
	return buf.String()
}

// ExportJSON re-runs the scan for the given targets and returns a JSON report
// as a string. Respects the TLS setting from the last RunScan call.
func (a *App) ExportJSON(targets []string, activeModules []string) string {
	results := a.runForExport(targets, activeModules, a.lastSkipTLS)
	if results == nil {
		return "{}"
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, results, true); err != nil {
		return fmt.Sprintf(`{"error": %q}`, err.Error())
	}
	return buf.String()
}

// ExportCompliancePDF generates a NIS2 compliance PDF from the serialised scan
// results already held in the frontend (resultsJSON is JSON.stringify(allResults)).
// lang is "en" or "de" and controls the report language.
// Opens a native save-file dialog; returns the saved path or "" on cancel/error.
func (a *App) ExportCompliancePDF(resultsJSON, lang string) string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: fmt.Sprintf("nis2-compliance-%s.pdf", time.Now().Format("2006-01-02")),
		Filters: []runtime.FileFilter{
			{DisplayName: "PDF Files (*.pdf)", Pattern: "*.pdf"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return ""
	}
	f, err := os.Create(path)
	if err != nil {
		showError(a, "PDF export failed", err)
		return ""
	}
	defer f.Close()

	payload := []byte(resultsJSON)
	if lang == "de" {
		if translated, err := applyFindingTranslations(payload, i18n.LoadGerman()); err == nil {
			payload = translated
		}
	}

	if err := report.WriteCompliancePDF(f, payload, lang); err != nil {
		showError(a, "PDF export failed", err)
		return ""
	}
	return path
}

// SaveFile opens a native save-file dialog and writes content to the chosen path.
// Returns the saved path or "" on cancel/error.
func (a *App) SaveFile(defaultFilename, content string) string {
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		DefaultFilename: defaultFilename,
		Filters: []runtime.FileFilter{
			{DisplayName: "HTML Files", Pattern: "*.html"},
			{DisplayName: "JSON Files", Pattern: "*.json"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return ""
	}
	if err := writeFile(path, content); err != nil {
		showError(a, "Export failed", err)
		return ""
	}
	return path
}

// showError displays a native error dialog. Centralises the repetitive
// runtime.MessageDialog call used across export methods.
func showError(a *App, title string, err error) {
	runtime.MessageDialog(a.ctx, runtime.MessageDialogOptions{
		Type:    runtime.ErrorDialog,
		Title:   title,
		Message: err.Error(),
	})
}
