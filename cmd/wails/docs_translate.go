package main

import (
	"encoding/json"

	"idenaro/internal/i18n"
	"idenaro/internal/nis2"
)

// applyFindingTranslations is used by ExportCompliancePDF to translate a
// serialised []ScanResultDTO at the JSON level before PDF rendering.
// It replaces description, recommendation, and NIS2 article labels with
// the German equivalents where available.
func applyFindingTranslations(data []byte, tx map[string]i18n.Translation) ([]byte, error) {
	var results []ScanResultDTO
	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			if t, ok := tx[f.ID]; ok {
				if t.Description != "" {
					f.Description = t.Description
				}
				if t.Recommendation != "" {
					f.Recommendation = t.Recommendation
				}
			}
			if german := nis2.LookupLocalized(f.Tags, "de"); len(german) > 0 {
				f.NIS2Articles = german
			}
		}
	}
	return json.Marshal(results)
}
