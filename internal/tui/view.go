package tui

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/charmbracelet/x/ansi"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/report"
)

var tabs = []string{"Sources", "Coverage", "Findings", "Next actions"}

func (s state) View() string {
	if s.width < 35 || s.height < 14 {
		return "KeyRadar — enlarge terminal (35×14 minimum).\nCtrl+C exits.\n> " + s.inputView(max(2, s.width-3))
	}
	width := min(100, s.width-2)
	roomy := s.height >= 24
	lines := []string{fmt.Sprintf("KeyRadar %s · %s", model.Version, tabs[s.page])}
	if roomy {
		lines = append([]string{""}, lines...)
	}
	if s.height >= 18 {
		if len(s.c.Runs) > 0 {
			var nav []string
			for i, name := range tabs {
				if i == s.page {
					name = "[" + name + "]"
				}
				nav = append(nav, name)
			}
			lines = append(lines, strings.Join(nav, "  →  "))
		} else {
			lines = append(lines, "Find known credential copies and track rotation.")
		}
	}
	lines = append(lines, "")
	if roomy {
		lines = append(lines, "")
	}
	choosing := s.wizard == nil && !s.picking && !s.removing && !s.busy
	if choosing {
		if s.height >= 20 {
			heading := "What would you like to do?"
			if s.page == 0 && len(s.scopes) > 0 {
				heading = "Review your sources, then start the scan."
			}
			if s.page == 1 {
				heading = "Review what was checked, then continue to findings."
			}
			if s.page == 2 {
				heading = "Review known credentials and open tasks."
			}
			lines = append(lines, heading)
			if roomy {
				lines = append(lines, "")
			}
		}
		for i, a := range s.actions() {
			prefix := "  "
			if i == s.menu {
				prefix = "› "
			}
			lines = append(lines, prefix+a.label)
		}
		lines = append(lines, "")
	}
	label := "Press Enter to choose, or type a command"
	hint := "↑↓ Select   Enter Continue   Esc Back   Ctrl+C Quit"
	secondary := "/help: commands"
	if len(s.c.Runs) > 0 {
		secondary = "Tab: sections · PgUp/PgDn: scroll · /help: commands"
	}
	if s.picking || s.removing {
		label = "Choose with ↑↓, then press Enter"
		secondary = "Esc returns to your selected sources."
	}
	if s.wizard != nil {
		label = s.wizard.fields[s.wizard.step].label
		hint = "Enter Next   Esc Back   Ctrl+U Clear"
		secondary = "Authentication is requested separately when you scan."
	}
	prompt := "> " + s.inputView(width-2)
	if s.busy {
		label = "Scanning selected sources…"
		prompt = "> Working…"
		hint = "Ctrl+C cancels and preserves completed observations."
	}
	footer := []string{}
	if roomy {
		footer = append(footer, "")
	}
	if s.notice != "" {
		footer = append(footer, s.notice)
	}
	if roomy && s.wizard != nil {
		// Treat source entry as a field with its own space, rather than a line
		// wedged between helper text and keyboard shortcuts.
		inner := width - 4
		field := "> " + s.inputView(inner-2)
		field += strings.Repeat(" ", max(0, inner-ansi.StringWidth(field)))
		blank := "│" + strings.Repeat(" ", width-2) + "│"
		footer = append(footer, label, "",
			"┌"+strings.Repeat("─", width-2)+"┐", blank,
			"│ "+field+" │", blank,
			"└"+strings.Repeat("─", width-2)+"┘", "", hint)
	} else if roomy {
		footer = append(footer, strings.Repeat("─", width), label, "", prompt, "", hint)
	} else {
		footer = append(footer, strings.Repeat("─", width), label, prompt, hint)
	}
	if s.height >= 18 {
		if roomy {
			footer = append(footer, "")
		}
		footer = append(footer, secondary)
	}
	body := s.content()
	room := max(1, min(12, s.height-len(lines)-len(footer)))
	start := min(s.offset, max(0, len(body)-room))
	if s.wizard != nil {
		start = 0
	}
	if s.picking || s.removing {
		start = max(0, 2+s.choice-room+1)
	}
	end := min(len(body), start+room)
	lines = append(lines, body[start:end]...)
	lines = append(lines, footer...)
	for i, line := range lines {
		// Sanitize untrusted labels without a byte limit that splits Unicode dividers.
		line = strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				return -1
			}
			return r
		}, line)
		lines[i] = " " + ansi.Truncate(line, width, "…")
	}
	return strings.Join(lines, "\n")
}

// A steady software caret stays visible even when the terminal hides its hardware cursor.
// Horizontally scroll metadata entry so the caret is always inside the viewport.
func (s state) inputView(width int) string {
	pos := min(max(s.cursor, 0), len(s.input))
	left := string(s.input[:pos])
	right := string(s.input[pos:])
	for ansi.StringWidth(left) > max(0, width-1) {
		r := []rune(left)
		left = string(r[1:])
	}
	value := left + "█" + right

	return ansi.Truncate(value, width, "")
}

func (s state) content() []string {
	if s.picking {
		lines := []string{"Where should KeyRadar look?", ""}
		for i, name := range sourceNames {
			prefix := "  "
			if i == s.choice {
				prefix = "› "
			}
			lines = append(lines, prefix+name)
		}
		return lines
	}
	if s.removing {
		lines := []string{"Remove which source from this selection?", ""}
		for i, sc := range s.scopes {
			prefix := "  "
			if i == s.choice {
				prefix = "› "
			}
			lines = append(lines, prefix+scopeLabel(sc))
		}
		return lines
	}
	if s.wizard != nil {
		w := s.wizard
		name := map[string]string{"local": "local file", "vercel": "Vercel", "railway": "Railway", "github": "GitHub"}[w.scope.Source]
		return []string{fmt.Sprintf("Add %s source · step %d of %d", name, w.step+1, len(w.fields)), "", w.fields[w.step].hint}
	}
	r, err := report.Build(s.c, false)
	if err != nil {
		return []string{"Case metadata could not be displayed."}
	}
	lines := []string{}
	switch s.page {
	case 0:
		for _, sc := range s.scopes {
			lines = append(lines, "• "+scopeLabel(sc))
		}
		if len(s.scopes) == 0 {
			lines = append(lines, "Choose sources: inspect your local file or selected cloud projects.", "Offline demo: explore a sample without connecting an account.")
		}
		if s.store == nil {
			lines = append(lines, "", "This session is not saved. Export a report before you quit.")
		}
	case 1:
		lines = append(lines, "Coverage: "+r.CoverageStatus, "")
		for _, v := range r.Coverage {
			lines = append(lines, v.Source+" / "+v.Scope+" : "+v.Status+" ("+v.Reason+")")
		}
		if len(r.Coverage) == 0 {
			lines = append(lines, "No collection yet. Esc goes back to source selection.")
		}
	case 2:
		if len(r.Credentials) == 0 && len(r.Tasks) == 0 {
			lines = append(lines, "No credentials or tasks yet. Esc goes back.")
		}
		for _, v := range r.Credentials {
			lines = append(lines, fmt.Sprintf("%s  %s  historical=%t  %s  copies=%d", v.ID, v.Issuer, v.Historical, v.Exposure, len(v.Locations)))
		}
		for _, t := range r.Tasks {
			lines = append(lines, t.ID+"  "+t.Action+" ["+t.Status+"]")
		}
	case 3:
		lines = append(lines, "Update your progress, inspect key usage, or export the findings.", "Issuer silence does not prove no consumers remain.")
		for _, v := range r.IssuerEvidence {
			last := "unknown"
			if v.LastUsedAt != nil {
				last = v.LastUsedAt.UTC().Format("2006-01-02 15:04:05Z")
			}
			lines = append(lines, v.CredentialID+" / "+v.Issuer+" "+v.Activity+" last="+last+" "+v.Source+" "+v.Reason)
		}
		lines = append(lines, fmt.Sprintf("Tool-access cleanup pending: %d", r.ToolAccessPending))
	}
	return lines
}
