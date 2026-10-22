// Package tui renders metadata only. Authentication runs with the screen suspended.
package tui

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/shenli/keyradar/internal/casefile"
	"github.com/shenli/keyradar/internal/cli"
	"github.com/shenli/keyradar/internal/issuer"
	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/report"
	"github.com/shenli/keyradar/internal/scan"
	"github.com/shenli/keyradar/internal/secure"
)

type done struct {
	c   *model.Case
	err error
}
type authDone struct{ err error }
type tick struct{}
type interrupted struct{}
type execFunc struct{ fn func() error }

func (e execFunc) Run() error        { return e.fn() }
func (execFunc) SetStdin(io.Reader)  {}
func (execFunc) SetStdout(io.Writer) {}
func (execFunc) SetStderr(io.Writer) {}

type state struct {
	c             *model.Case
	scopes        []model.Scope
	page          int
	width, height int
	offset        int
	busy          bool
	input         []rune
	cursor        int
	menu          int
	removing      bool
	picking       bool
	choice        int
	wizard        *sourceWizard
	notice        string
	store         *casefile.Store
	start         func([]model.Scope) tea.Cmd
	execute       func(*model.Case, []model.Scope) tea.Cmd
	record        func(*model.Case) tea.Cmd
	check         func(*model.Case) tea.Cmd
	export        func(*model.Case) tea.Cmd
	progress      chan scan.Progress
	cancel        context.CancelFunc
	ctx           context.Context
}

func clone(c *model.Case) *model.Case {
	b, _ := json.Marshal(c)
	var out model.Case
	json.Unmarshal(b, &out)
	return &out
}
func Run(ctx context.Context, c *model.Case, store *casefile.Store, scopes []model.Scope) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if len(scopes) == 0 {
		scopes = append([]model.Scope(nil), c.Scopes...)
	}
	progress := make(chan scan.Progress, 32)
	// The auth handle is a closure owned by the controller, never a model/message field.
	var tokens map[string]secure.Token
	s := state{c: c, scopes: scopes, store: store, width: 90, height: 28, progress: progress, cancel: cancel, ctx: ctx}
	s.start = func(sc []model.Scope) tea.Cmd {
		return tea.Exec(execFunc{fn: func() error { var e error; tokens, e = cli.PromptTokens(sc); return e }}, func(e error) tea.Msg { return authDone{err: e} })
	}
	s.execute = func(c *model.Case, sc []model.Scope) tea.Cmd {
		return func() tea.Msg {
			copy := clone(c)
			e := scan.New().Scan(ctx, copy, scan.Options{Scopes: sc, Tokens: tokens}, func(p scan.Progress) {
				select {
				case progress <- p:
				default:
				}
			})
			tokens = nil
			return done{c: copy, err: e}
		}
	}
	s.record = func(c *model.Case) tea.Cmd {
		copy := clone(c)
		return tea.Exec(execFunc{fn: func() error { return cli.RecordInteractive(copy) }}, func(e error) tea.Msg { return done{c: copy, err: e} })
	}
	s.check = func(c *model.Case) tea.Cmd {
		copy := clone(c)
		return tea.Exec(execFunc{fn: func() error {
			id, e := cli.PromptLine("Credential ID to check")
			if e != nil {
				return e
			}
			cr := copy.Credential(id)
			if cr == nil {
				return errors.New("credential not found")
			}
			x := issuer.New()
			var token secure.Token
			if cr.Issuer == "aws" {
				p, err := cli.PromptLine("Explicit static AWS audit profile")
				if err != nil {
					return err
				}
				x, e = issuer.StaticProfile(ctx, p)
			} else if cr.Issuer == "openai" {
				token, e = cli.PromptToken("OpenAI project-key audit credential")
			} else {
				return errors.New("automated checks support AWS and OpenAI")
			}
			if e != nil {
				return e
			}
			return x.Check(ctx, copy, []string{id}, cr.Issuer, token)
		}}, func(e error) tea.Msg { return done{c: copy, err: e} })
	}
	s.export = func(c *model.Case) tea.Cmd {
		return tea.Exec(execFunc{fn: func() error {
			path, e := cli.PromptLine("New shareable JSON export path (existing files are refused)")
			if e != nil {
				return e
			}
			f, e := secure.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if e != nil {
				return errors.New("export destination unavailable")
			}
			defer f.Close()
			return report.Write(f, c, "json", true)
		}}, func(e error) tea.Msg { return done{c: c, err: e} })
	}
	p := tea.NewProgram(s, tea.WithAltScreen(), tea.WithoutSignalHandler())
	_, e := p.Run()
	if errors.Is(e, tea.ErrProgramKilled) && ctx.Err() != nil {
		return nil
	}
	if e != nil {
		return errors.New("TUI terminated")
	}
	return nil
}
func (s state) Init() tea.Cmd {
	if s.ctx == nil {
		return nil
	}
	return func() tea.Msg { <-s.ctx.Done(); return interrupted{} }
}
func (s state) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch v := msg.(type) {
	case tea.WindowSizeMsg:
		s.width = v.Width
		s.height = v.Height
	case authDone:
		if v.err != nil {
			s.notice = v.err.Error()
			s.busy = false
			return s, nil
		}
		s.busy = true
		s.moveTo(1)
		s.notice = "Collecting selected scopes…"
		return s, tea.Batch(s.execute(s.c, s.scopes), s.nextProgress())
	case tick:
		if s.busy {
			select {
			case p := <-s.progress:
				s.notice = p.Source + ": " + p.Status
			default:
			}
			return s, s.nextProgress()
		}
	case interrupted:
		if !s.busy {
			return s, tea.Quit
		}
		s.notice = "Cancelling; preserving completed observations…"
	case done:
		s.busy = false
		if v.err != nil {
			s.notice = v.err.Error()
		} else {
			s.c = v.c
			s.notice = "Operation complete; inspect coverage and evidence."
			if s.store != nil {
				if e := s.store.Save(s.c); e != nil {
					s.notice = e.Error()
				}
			}
		}
		if s.ctx != nil && s.ctx.Err() != nil {
			return s, tea.Quit
		}
	case tea.KeyMsg:
		return s.handleKey(v)
	}
	return s, nil
}
func (s state) nextProgress() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return tick{} })
}
