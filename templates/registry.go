// Package templates embeds reviewed incident guidance. Templates are data, not executable instructions.
package templates

import (
	"embed"
	"encoding/json"
	"errors"
)

//go:embed *.json
var files embed.FS

type Template struct {
	ID                                  string   `json:"id"`
	Version                             string   `json:"version"`
	Provider                            string   `json:"provider"`
	WindowStart                         *string  `json:"window_start"`
	WindowEnd                           *string  `json:"window_end"`
	ReadableExposure                    string   `json:"readable_exposure"`
	UnreadableExposure                  string   `json:"unreadable_exposure"`
	HistoricalExclusionRequiresEvidence bool     `json:"historical_exclusion_requires_evidence"`
	Sources                             []string `json:"sources"`
	Notes                               []string `json:"notes"`
}

func Load(id string) (Template, error) {
	if id != "custom" && id != "vercel-apr-2026" {
		return Template{}, errors.New("unknown incident template")
	}
	b, err := files.ReadFile(id + ".json")
	if err != nil {
		return Template{}, errors.New("incident template unavailable")
	}
	var t Template
	if json.Unmarshal(b, &t) != nil || t.ID != id || t.Version != "1" {
		return Template{}, errors.New("invalid incident template")
	}
	return t, nil
}

func Exposure(id, source, readability string) string {
	t, err := Load(id)
	if err != nil || source != t.Provider {
		return "unknown"
	}
	if readability == "readable" {
		return t.ReadableExposure
	}
	return t.UnreadableExposure
}
