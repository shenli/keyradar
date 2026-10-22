package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/scan"
)

func TestViewsAndNavigation(t *testing.T) {
	s := state{c: scan.Demo(), width: 100, height: 30}
	for i := 0; i < 4; i++ {
		v := s.View()
		if strings.Contains(v, "KEYRADAR_SYNTHETIC_NEVER_VALID_27d8d9") {
			t.Fatal("value rendered")
		}
		next, _ := s.Update(tea.KeyMsg{Type: tea.KeyTab})
		s = next.(state)
	}
	if s.page != 0 {
		t.Fatal("tab navigation")
	}
	next, _ := s.Update(tea.WindowSizeMsg{Width: 20, Height: 5})
	if !strings.Contains(next.View(), "enlarge") {
		t.Fatal("narrow terminal not handled")
	}
}

func input(s state, value string) state {
	next, _ := s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)})
	return next.(state)
}
func enter(s state) state { next, _ := s.Update(tea.KeyMsg{Type: tea.KeyEnter}); return next.(state) }
func fresh() state        { return state{c: model.New("custom", time.Now()), width: 100, height: 24} }

func TestPromptWaitsForEnterAndKeepsCaretVisible(t *testing.T) {
	s := fresh()
	s = input(s, "/demo")
	if len(s.c.Runs) != 0 {
		t.Fatal("typing executed a command")
	}
	if !strings.Contains(s.View(), "> /demo█") {
		t.Fatal("focused prompt missing")
	}
	s = enter(s)
	if len(s.c.Runs) == 0 || len(s.input) != 0 {
		t.Fatal("Enter did not execute and clear prompt")
	}
	for _, size := range []struct{ w, h int }{{100, 24}, {40, 14}, {60, 18}} {
		s.width = size.w
		s.height = size.h
		view := s.View()
		if len(strings.Split(view, "\n")) > size.h || !strings.Contains(view, "█") {
			t.Fatal("prompt outside viewport")
		}
		for _, line := range strings.Split(view, "\n") {
			if ansi.StringWidth(line) > size.w {
				t.Fatal("line wrapped outside viewport")
			}
		}
	}
}

func TestGuidedLocalPathWithSpacesAndExplicitScan(t *testing.T) {
	s := fresh()
	s = enter(input(s, "/add"))
	s = enter(s)
	if s.wizard == nil || s.wizard.scope.Source != "local" {
		t.Fatal("source picker did not open local form")
	}
	s = enter(input(s, "./task-worker directory/input.env"))
	if s.wizard != nil || len(s.scopes) != 1 || !strings.HasSuffix(s.scopes[0].File, "task-worker directory/input.env") {
		t.Fatal("path with spaces not added")
	}
	if len(s.c.Runs) != 0 || s.busy {
		t.Fatal("selecting source started collection")
	}
	started := false
	s.start = func(sc []model.Scope) tea.Cmd { started = true; return nil }
	s = enter(input(s, "/scan"))
	if !started || !s.busy {
		t.Fatal("explicit scan did not start")
	}
}

func TestGuidedGitHubOptionalEnvironmentAndCancel(t *testing.T) {
	s := fresh()
	s = enter(input(s, "/add"))
	s = enter(input(s, "github"))
	s = enter(input(s, "owner/repo"))
	s = enter(s)
	if len(s.scopes) != 1 || s.scopes[0].Environment != "" {
		t.Fatal("repository-only selection failed")
	}
	s = enter(input(s, "/add"))
	s = enter(input(s, "railway"))
	s = enter(input(s, "project"))
	next, _ := s.Update(tea.KeyMsg{Type: tea.KeyEsc})
	s = next.(state)
	if s.wizard == nil || s.wizard.step != 0 || string(s.input) != "project" {
		t.Fatal("back lost the previous field")
	}
	s = key(s, tea.KeyEsc)
	s = key(s, tea.KeyEsc)
	if s.wizard != nil || s.picking || len(s.scopes) != 1 {
		t.Fatal("cancel altered selected scopes")
	}
}

func TestPickerValidationAndTypingAreNotGlobalShortcuts(t *testing.T) {
	s := fresh()
	s = enter(input(s, "/add"))
	s = enter(input(s, "vercel"))
	s = enter(input(s, "team"))
	s = enter(input(s, "project"))
	s = enter(input(s, "invalid-environment"))
	if len(s.scopes) != 0 || s.wizard == nil || s.wizard.step != 2 {
		t.Fatal("invalid scope committed or field context lost")
	}
	s = key(s, tea.KeyCtrlU)
	s = input(s, "quick-team")
	if string(s.input) != "quick-team" {
		t.Fatal("typing interpreted as a shortcut")
	}
}

func TestInputEditingAndPasteBoundary(t *testing.T) {
	s := fresh()
	s = input(s, "/demx")
	next, _ := s.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	s = next.(state)
	s = input(s, "o")
	if string(s.input) != "/demo" {
		t.Fatal("editing failed")
	}
	s = enter(s)
	next, _ = s.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/quit\n"), Paste: true})
	s = next.(state)
	if len(s.input) != 0 {
		t.Fatal("multiline paste accepted")
	}
	s = input(s, "sk-proj-SYNTHETIC_NEVER_VALID")
	if len(s.input) != 0 || strings.Contains(s.View(), "SYNTHETIC_NEVER_VALID") {
		t.Fatal("recognized token paste rendered")
	}
	s.input = []rune(strings.Repeat("界", 100))
	s.cursor = len(s.input)
	if !strings.Contains(s.inputView(20), "█") || ansi.StringWidth(s.inputView(20)) > 20 {
		t.Fatal("wide text hid caret")
	}
}

func TestSmallPickerKeepsSelectedSourceVisible(t *testing.T) {
	s := fresh()
	s.height = 14
	s.width = 40
	s = enter(input(s, "/add"))
	for i := 0; i < len(sourceNames); i++ {
		s.choice = i
		if !strings.Contains(s.View(), "› "+sourceNames[i]) {
			t.Fatal("selected source scrolled out of view")
		}
	}
}

func key(s state, k tea.KeyType) state { next, _ := s.Update(tea.KeyMsg{Type: k}); return next.(state) }

func TestMenuFlowNeedsNoCommands(t *testing.T) {
	s := fresh()
	s = enter(s)
	if !s.picking {
		t.Fatal("default Enter did not open source picker")
	}
	s = enter(s)
	s = enter(input(s, "./input.env"))
	if len(s.scopes) != 1 || s.busy {
		t.Fatal("selection must not start a scan")
	}
	// Remove an accidental selection without restarting the app.
	s = key(s, tea.KeyDown)
	s = key(s, tea.KeyDown)
	s = enter(s)
	if !s.removing {
		t.Fatal("remove source action unavailable")
	}
	s = enter(s)
	if len(s.scopes) != 0 || s.removing {
		t.Fatal("source not removed")
	}
	s = key(s, tea.KeyDown)
	s = enter(s)
	if len(s.c.Runs) == 0 || s.page != 1 {
		t.Fatal("demo did not open coverage")
	}
	s = enter(s)
	if s.page != 2 {
		t.Fatal("coverage did not lead to findings")
	}
	s = enter(s)
	if s.page != 3 {
		t.Fatal("findings did not lead to next actions")
	}
	s = key(s, tea.KeyEsc)
	if s.page != 2 {
		t.Fatal("Back did not return to findings")
	}
}

func TestLargeTerminalKeepsActionsAndPromptTogether(t *testing.T) {
	s := fresh()
	s.width = 400
	s.height = 100
	view := s.View()
	if len(strings.Split(view, "\n")) > 30 {
		t.Fatal("home fills terminal with blank padding")
	}
	if !strings.Contains(view, "› Choose sources to scan") || !strings.Contains(view, "Esc Back") || !strings.Contains(view, "> █") {
		t.Fatal("primary action or navigation missing")
	}
	if !utf8.ValidString(view) || strings.ContainsAny(view, "�") {
		t.Fatal("broken Unicode")
	}
	for _, line := range strings.Split(view, "\n") {
		if ansi.StringWidth(line) > 101 {
			t.Fatal("unbounded line length")
		}
		if strings.Contains(line, "─") && strings.TrimSpace(line) != strings.Repeat("─", 100) {
			t.Fatal("divider truncated")
		}
	}
	t.Log("Large-terminal home:\n" + view)
	form := enter(fresh())
	form = enter(input(form, "railway"))
	t.Log("Railway form at 100×24:\n" + form.View())
	// Short windows must still show the selected action and the input together.
	s.height = 14
	s.width = 40
	s = enter(s)
	s = enter(s)
	s = enter(input(s, "./input.env"))
	if len(strings.Split(s.View(), "\n")) > 14 {
		t.Fatal("compact selection overflows terminal")
	}
}
