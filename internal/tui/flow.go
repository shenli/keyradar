package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/scan"
)

type action struct{ label, command string }

func (s state) actions() []action {
	switch s.page {
	case 0:
		if len(s.c.Runs) > 0 {
			return []action{{"Review scan results", "coverage"}, {"Scan these sources again", "scan"}}
		}
		if len(s.scopes) == 0 {
			return []action{{"Choose sources to scan", "add"}, {"Try the offline demo", "demo"}}
		}
		return []action{{fmt.Sprintf("Scan %d selected source(s)", len(s.scopes)), "scan"}, {"Add another source", "add"}, {"Remove a source", "remove"}}
	case 1:
		return []action{{"Review findings", "credentials"}, {"Scan these sources again", "scan"}}
	case 2:
		return []action{{"Review next actions", "issuer"}}
	case 3:
		return []action{{"Record rotation progress", "record"}, {"Check issuer activity", "check"}, {"Export a shareable report", "export"}}
	}
	return nil
}
func (s *state) moveTo(page int) { s.page = page; s.menu = 0; s.offset = 0; s.notice = "" }
func (s state) back() (tea.Model, tea.Cmd) {
	s.notice = ""
	if s.wizard != nil {
		if s.wizard.step > 0 {
			w := *s.wizard
			w.step--
			s.wizard = &w
			s.loadField()
		} else {
			s.wizard = nil
			s.picking = true
			s.resetInput()
		}
	} else if s.picking || s.removing {
		s.picking = false
		s.removing = false
		s.resetInput()
		s.menu = 0
	} else if len(s.input) > 0 {
		s.resetInput()
	} else if s.page > 0 {
		s.moveTo(s.page - 1)
	}
	return s, nil
}
func (s *state) loadField() {
	w := s.wizard
	value := ""
	switch w.fields[w.step].key {
	case "file":
		value = w.scope.File
	case "team":
		value = w.scope.Team
	case "project":
		value = w.scope.Project
	case "environment":
		value = w.scope.Environment
	case "service":
		value = w.scope.Service
	}
	s.input = []rune(value)
	s.cursor = len(s.input)
}

// Validate each field before proceeding; missing later fields get temporary valid
// placeholders only for validation, never in the draft or selected scopes.
func validateDraft(w sourceWizard) error {
	sc := w.scope
	if sc.Project == "" {
		sc.Project = "project"
		if sc.Source == "github" {
			sc.Project = "owner/repo"
		}
	}
	if sc.Team == "" {
		sc.Team = "team"
	}
	if sc.Service == "" {
		sc.Service = "service"
	}
	if sc.Environment == "" && sc.Source != "github" {
		sc.Environment = "production"
	}
	return scan.ValidateScopes([]model.Scope{sc})
}

func scopeLabel(sc model.Scope) string {
	if sc.Source == "local" {
		return "Local file · " + sc.File
	}
	parts := []string{sc.Source, sc.Project}
	if sc.Environment != "" {
		parts = append(parts, sc.Environment)
	}
	if sc.Service != "" {
		parts = append(parts, sc.Service)
	}
	return strings.Join(parts, " · ")
}
