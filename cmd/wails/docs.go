package main

import (
	"embed"
	"strings"
	"unicode"

	"idenaro/internal/i18n"
)

//go:embed docs
var docFS embed.FS

// GetAppVersion returns the application version string shown in the title bar.
func (a *App) GetAppVersion() string { return "1.1.0" }

// GetDocContent returns the raw markdown for a documentation page.
// path must be a safe relative path such as "nis2/21-2-a" or "modules/oidc".
// Returns empty string if the path is invalid or the file is not found.
func (a *App) GetDocContent(path string) string {
	if !isSafePath(path) {
		return ""
	}
	// Module docs live in the shared i18n package so the CLI can also embed them.
	if strings.HasPrefix(path, "modules/") {
		data, err := i18n.DocFS.ReadFile("docs/" + path + ".md")
		if err != nil {
			return ""
		}
		return string(data)
	}
	data, err := docFS.ReadFile("docs/" + path + ".md")
	if err != nil {
		return ""
	}
	return string(data)
}

// isSafePath rejects any path that contains characters outside the allowed set
// or attempts directory traversal.
func isSafePath(path string) bool {
	if strings.Contains(path, "..") || strings.HasPrefix(path, "/") {
		return false
	}
	for _, c := range path {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' && c != '/' {
			return false
		}
	}
	return true
}
