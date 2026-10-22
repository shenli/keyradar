package tui

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/scan"
)

type sourceField struct {
	key, label, hint string
	optional         bool
}
type sourceWizard struct {
	scope  model.Scope
	fields []sourceField
	step   int
}

var sourceNames = []string{"Local .env file", "Vercel", "Railway", "GitHub Actions"}

func (s *state) resetInput() { s.input = nil; s.cursor = 0 }
func (s state) handleKey(v tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := v.String()
	if k == "ctrl+c" {
		if s.cancel != nil {
			s.cancel()
		}
		s.notice = "Cancelling; preserving completed observations…"
		if !s.busy {
			return s, tea.Quit
		}
		return s, nil
	}
	if s.busy {
		return s, nil
	}
	switch k {
	case "esc":
		return s.back()
	case "tab", "shift+tab":
		if s.wizard == nil && !s.picking && !s.removing && len(s.c.Runs) > 0 {
			delta := 1
			if k == "shift+tab" {
				delta = 3
			}
			s.moveTo((s.page + delta) % 4)
		}
	case "up", "down":
		delta := 1
		if k == "up" {
			delta = -1
		}
		if s.picking {
			s.choice = (s.choice + delta + len(sourceNames)) % len(sourceNames)
		} else if s.removing {
			s.choice = (s.choice + delta + len(s.scopes)) % len(s.scopes)
		} else if s.wizard == nil {
			actions := s.actions()
			s.menu = (s.menu + delta + len(actions)) % len(actions)
		}
	case "pgdown", "pgup":
		if s.wizard == nil && !s.picking && !s.removing {
			delta := 8
			if k == "pgup" {
				delta = -8
			}
			s.offset = max(0, s.offset+delta)
		}
	case "left":
		s.cursor = max(0, s.cursor-1)
	case "right":
		s.cursor = min(len(s.input), s.cursor+1)
	case "home", "ctrl+a":
		s.cursor = 0
	case "end", "ctrl+e":
		s.cursor = len(s.input)
	case "ctrl+u":
		s.resetInput()
	case "backspace", "ctrl+h":
		if s.cursor > 0 {
			s.input = append(s.input[:s.cursor-1], s.input[s.cursor:]...)
			s.cursor--
		}
	case "delete":
		if s.cursor < len(s.input) {
			s.input = append(s.input[:s.cursor], s.input[s.cursor+1:]...)
		}
	case "enter":
		text := strings.TrimSpace(string(s.input))
		if s.picking {
			return s.chooseSource(text)
		}
		if s.removing {
			if text != "" {
				s.notice = "Use the arrow keys to choose a source, then press Enter."
				return s, nil
			}
			s.scopes = append(append([]model.Scope(nil), s.scopes[:s.choice]...), s.scopes[s.choice+1:]...)
			s.removing = false
			s.menu = 0
			s.notice = "Source removed from this selection."
			return s, nil
		}
		if s.wizard != nil {
			return s.acceptField(text)
		}
		s.resetInput()
		if text == "" {
			a := s.actions()
			text = a[min(s.menu, len(a)-1)].command
		}
		return s.command(text)
	default:
		if v.Type == tea.KeyRunes || v.Type == tea.KeySpace {
			text := string(v.Runes)
			if v.Type == tea.KeySpace {
				text = " "
			}
			for _, r := range text {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					s.notice = "Enter one line of commands or source metadata. Tokens belong in the hidden prompt."
					return s, nil
				}
			}
			if len(s.input)+len([]rune(text)) > 4096 {
				s.notice = "Input is too long."
				return s, nil
			}
			next := append([]rune(nil), s.input[:s.cursor]...)
			next = append(next, []rune(text)...)
			next = append(next, s.input[s.cursor:]...)
			// Reject recognizable token pastes before they enter the rendered input buffer.
			for _, prefix := range []string{"sk-", "sk_live_", "rk_live_", "ghp_", "github_pat_"} {
				if strings.HasPrefix(strings.TrimSpace(string(next)), prefix) {
					s.resetInput()
					s.notice = "Do not paste credentials here. Authentication uses a separate hidden prompt."
					return s, nil
				}
			}
			s.input = next
			s.cursor += len([]rune(text))
		}
	}
	return s, nil
}

func (s state) command(text string) (tea.Model, tea.Cmd) {
	switch strings.TrimPrefix(strings.ToLower(text), "/") {
	case "":
		return s, nil
	case "quit", "q", "exit":
		return s, tea.Quit
	case "help", "?":
		s.notice = "/add · /scan · /demo · /record · /check · /export · /quit. Tab changes views."
	case "sources":
		s.moveTo(0)
	case "coverage":
		s.moveTo(1)
	case "credentials", "tasks":
		s.moveTo(2)
	case "issuer":
		s.moveTo(3)
	case "remove":
		if len(s.c.Runs) > 0 || len(s.scopes) == 0 {
			s.notice = "Only unscanned selections can be removed."
			break
		}
		s.moveTo(0)
		s.removing = true
		s.choice = 0
	case "add", "a":
		if len(s.c.Runs) > 0 {
			s.notice = "This case's scope is fixed. Start a new case to select different sources."
			break
		}
		s.moveTo(0)
		s.picking = true
		s.choice = 0
		s.notice = "Choose a source. No credentials are needed to select it."
	case "scan", "s":
		if len(s.scopes) == 0 {
			s.picking = true
			s.choice = 0
			s.page = 0
			s.notice = "Choose your first source."
			break
		}
		sc, err := scan.CanonicalScopes(s.scopes)
		if err != nil {
			s.notice = err.Error()
			break
		}
		if len(s.c.Scopes) > 0 && !scan.SameScopes(s.c.Scopes, sc) {
			s.notice = "Scope differs from case; start a new case."
			break
		}
		s.scopes = sc
		s.busy = true
		s.notice = "Opening hidden authentication prompts…"
		return s, s.start(sc)
	case "record", "r":
		return s, s.record(s.c)
	case "check", "i":
		return s, s.check(s.c)
	case "export", "e":
		return s, s.export(s.c)
	case "demo", "d":
		if len(s.c.Runs) > 0 {
			s.notice = "Demo requires a new case."
			break
		}
		s.c = scan.Demo()
		s.scopes = s.c.Scopes
		s.moveTo(1)
		s.notice = "Offline synthetic demonstration. Review what was checked, then continue to findings."
		if s.store != nil {
			if err := s.store.Save(s.c); err != nil {
				s.notice = err.Error()
			}
		}
	default:
		s.notice = "Unknown command. Enter /help to see available commands."
	}
	return s, nil
}

func (s state) chooseSource(text string) (tea.Model, tea.Cmd) {
	if text != "" {
		switch strings.ToLower(text) {
		case "1", "local":
			s.choice = 0
		case "2", "vercel":
			s.choice = 1
		case "3", "railway":
			s.choice = 2
		case "4", "github":
			s.choice = 3
		default:
			s.notice = "Choose with ↑↓ and Enter, or type local, vercel, railway or github."
			return s, nil
		}
	}
	w := &sourceWizard{}
	switch s.choice {
	case 0:
		w.scope.Source = "local"
		w.fields = []sourceField{{"file", "Local .env path", "Absolute or relative path; spaces are supported. No file contents.", false}}
	case 1:
		w.scope.Source = "vercel"
		w.fields = []sourceField{{"team", "Vercel team ID", "Enter the team ID, not a token.", false}, {"project", "Vercel project ID", "Enter the project ID.", false}, {"environment", "Vercel environment", "production, preview or development", false}}
	case 2:
		w.scope.Source = "railway"
		w.fields = []sourceField{{"project", "Railway project ID", "Enter the project ID, not a token.", false}, {"environment", "Railway environment ID", "Enter the environment ID.", false}, {"service", "Railway service ID", "Enter the service ID.", false}}
	case 3:
		w.scope.Source = "github"
		w.fields = []sourceField{{"project", "GitHub repository", "owner/repository", false}, {"environment", "GitHub environment (optional)", "Leave blank for repository secrets, or enter an environment name.", true}}
	}
	s.wizard = w
	s.picking = false
	s.resetInput()
	s.notice = ""
	return s, nil
}

func (s state) acceptField(text string) (tea.Model, tea.Cmd) {
	w := *s.wizard // Update a value copy so rejected input never commits a draft scope.
	f := w.fields[w.step]
	if text == "" && !f.optional {
		s.notice = "This field is required."
		return s, nil
	}
	switch f.key {
	case "file":
		if strings.HasPrefix(text, "~/") {
			home, err := os.UserHomeDir()
			if err != nil {
				s.notice = "Home directory unavailable; enter an absolute path."
				return s, nil
			}
			text = filepath.Join(home, text[2:])
		}
		w.scope.File = text
	case "team":
		w.scope.Team = text
	case "project":
		w.scope.Project = text
	case "environment":
		w.scope.Environment = text
	case "service":
		w.scope.Service = text
	}
	if err := validateDraft(w); err != nil {
		s.notice = err.Error() + ". Correct this field to continue."
		return s, nil
	}
	if w.step+1 < len(w.fields) {
		w.step++
		s.wizard = &w
		s.loadField()
		s.notice = ""
		return s, nil
	}
	scopes := append(append([]model.Scope(nil), s.scopes...), w.scope)
	canonical, err := scan.CanonicalScopes(scopes)
	if err != nil {
		s.notice = err.Error() + ". Esc goes back to edit your selection."
		return s, nil
	}
	s.scopes = canonical
	s.wizard = nil
	s.resetInput()
	s.menu = 0
	s.notice = "Source added. Review your selection, then press Enter to scan."
	return s, nil
}
