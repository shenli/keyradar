// Package cli provides machine-readable commands and independent-terminal authentication.
package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/shenli/keyradar/internal/app"
	"github.com/shenli/keyradar/internal/casefile"
	"github.com/shenli/keyradar/internal/issuer"
	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/report"
	"github.com/shenli/keyradar/internal/scan"
	"github.com/shenli/keyradar/internal/secure"
)

type UI func(context.Context, *model.Case, *casefile.Store, []model.Scope) error
type stringsFlag []string

func (s *stringsFlag) String() string     { return "" }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

type selection struct {
	files, projects, envs, repos, ghenvs stringsFlag
	team, rp, re, rs                     string
	railwayProjectToken                  bool
}

func (s *selection) flags(f *flag.FlagSet) {
	f.Var(&s.files, "local-file", "explicit .env file (repeatable)")
	f.Var(&s.projects, "vercel-project", "Vercel project ID (repeatable)")
	f.Var(&s.envs, "environment", "Vercel production/preview/development (repeatable)")
	f.StringVar(&s.team, "vercel-team", "", "Vercel team ID")
	f.StringVar(&s.rp, "railway-project", "", "Railway project ID")
	f.StringVar(&s.re, "railway-environment", "", "Railway environment ID")
	f.StringVar(&s.rs, "railway-service", "", "Railway service ID")
	f.BoolVar(&s.railwayProjectToken, "railway-project-token", false, "use a Railway project token instead of account token")
	f.Var(&s.repos, "github-repo", "owner/repository (repeatable)")
	f.Var(&s.ghenvs, "github-environment", "owner/repository:environment (repeatable)")
}
func (s *selection) scopes() ([]model.Scope, error) {
	var scopes []model.Scope
	for _, p := range s.files {
		scopes = append(scopes, model.Scope{Source: "local", File: p})
	}
	for _, p := range s.projects {
		if len(s.envs) == 0 {
			return nil, errors.New("Vercel requires an explicit --environment")
		}
		for _, e := range s.envs {
			scopes = append(scopes, model.Scope{Source: "vercel", Team: s.team, Project: p, Environment: e})
		}
	}
	if s.rp != "" || s.re != "" || s.rs != "" {
		scopes = append(scopes, model.Scope{Source: "railway", Project: s.rp, Environment: s.re, Service: s.rs})
	}
	for _, p := range s.repos {
		scopes = append(scopes, model.Scope{Source: "github", Project: p})
	}
	for _, p := range s.ghenvs {
		repo, env, ok := strings.Cut(p, ":")
		if !ok || env == "" {
			return nil, errors.New("GitHub environment must be owner/repository:environment")
		}
		scopes = append(scopes, model.Scope{Source: "github", Project: repo, Environment: env})
	}
	return scopes, nil
}
func ParseScopes(args []string) ([]model.Scope, error) {
	f := flag.NewFlagSet("scope", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var s selection
	s.flags(f)
	if f.Parse(args) != nil || f.NArg() != 0 {
		return nil, errors.New("invalid scope flags")
	}
	sc, e := s.scopes()
	if e != nil {
		return nil, e
	}
	return scan.CanonicalScopes(sc)
}
func PromptToken(label string) (secure.Token, error) {
	f, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return secure.Token{}, errors.New("authentication requires an independent terminal")
	}
	defer f.Close()
	if !term.IsTerminal(int(f.Fd())) {
		return secure.Token{}, errors.New("authentication requires a terminal")
	}
	fmt.Fprintf(f, "%s (hidden): ", secure.Text(label))
	b, e := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(f)
	if e != nil {
		return secure.Token{}, errors.New("authentication input failed")
	}
	defer clear(b)
	if len(b) == 0 || len(b) > 8192 || strings.ContainsAny(string(b), "\r\n\x00") {
		return secure.Token{}, errors.New("invalid authentication input")
	}
	return secure.NewToken(string(b)), nil
}
func PromptTokens(scopes []model.Scope) (map[string]secure.Token, error) {
	tokens := map[string]secure.Token{}
	for _, s := range scopes {
		if s.Source == "local" || tokens[s.Source].Reveal() != "" {
			continue
		}
		t, e := PromptToken(s.Source + " read token")
		if e != nil {
			return nil, e
		}
		tokens[s.Source] = t
	}
	return tokens, nil
}
func PromptLine(label string) (string, error) {
	f, e := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if e != nil {
		return "", errors.New("interactive entry requires a terminal")
	}
	defer f.Close()
	fmt.Fprintf(f, "%s: ", secure.Text(label))
	s, e := bufio.NewReader(io.LimitReader(f, 4097)).ReadString('\n')
	if e != nil || len(s) > 4096 {
		return "", errors.New("input unavailable or too long")
	}
	return strings.TrimSpace(s), nil
}
func flags(name string) *flag.FlagSet {
	f := flag.NewFlagSet(name, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	return f
}
func parse(f *flag.FlagSet, args []string) error {
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid arguments; run keyradar help")
	}
	return nil
}

const help = `KeyRadar — local credential incident response (alpha)

  keyradar demo [--format markdown|json] [--shareable] [--case DIRECTORY]
  keyradar scan [explicit source flags] [--incident vercel-apr-2026|custom]
                [--case DIRECTORY] [--format markdown|json] [--shareable]
  keyradar tui [--case DIRECTORY] [explicit source flags]
  keyradar report --case DIRECTORY [--format markdown|json] [--shareable]
  keyradar record --case DIRECTORY
  keyradar issuer check --case DIRECTORY --credential ID --issuer aws|openai
                       [--aws-profile NAME]
  keyradar clean --case DIRECTORY [--forget]
  keyradar version

Sources:
  --local-file FILE (repeatable; no recursive scan)
  --vercel-team ID --vercel-project ID --environment production|preview|development
  --railway-project ID --railway-environment ID --railway-service ID
  --railway-project-token (use project-token header)
  --github-repo OWNER/REPO --github-environment OWNER/REPO:ENV (repeatable)

Tokens are prompted in your independent terminal; no token arguments or ambient
credential discovery. AWS supports explicitly selected static profiles only.
Exit 0: command succeeded; 2: usable partial evidence; 1: failed. Never an all-clear.
`

func Run(ctx context.Context, args []string, out, errout io.Writer, ui UI) int {
	e, partial := run(ctx, args, out, ui)
	if e != nil {
		fmt.Fprintln(errout, "keyradar:", e.Error())
		return 1
	}
	if partial {
		return 2
	}
	return 0
}
func run(ctx context.Context, args []string, out io.Writer, ui UI) (error, bool) {
	if len(args) == 0 {
		if term.IsTerminal(int(os.Stdin.Fd())) && ui != nil {
			return ui(ctx, model.New("vercel-apr-2026", time.Now()), nil, nil), false
		}
		fmt.Fprint(out, help)
		return nil, false
	}
	switch args[0] {
	case "help", "--help", "-h":
		fmt.Fprint(out, help)
		return nil, false
	case "version", "--version":
		fmt.Fprintln(out, model.Version)
		return nil, false
	}
	cmd := args[0]
	args = args[1:]
	if cmd == "issuer" {
		if len(args) == 0 || args[0] != "check" {
			return errors.New("expected issuer check"), false
		}
		return check(ctx, args[1:], out)
	}
	f := flags(cmd)
	path := f.String("case", "", "metadata-only case directory")
	format := f.String("format", "markdown", "markdown or json")
	share := f.Bool("shareable", false, "omit external identifiers")
	incident := f.String("incident", "vercel-apr-2026", "incident template")
	scenario := f.String("scenario", "vercel-apr-2026", "demo scenario")
	forget := f.Bool("forget", false, "forget case despite pending token cleanup")
	var sel selection
	sel.flags(f)
	if e := parse(f, args); e != nil {
		return e, false
	}
	if !model.In(*format, "json", "markdown") || !model.In(*incident, "vercel-apr-2026", "custom") {
		return errors.New("invalid report format or incident"), false
	}
	if !model.In(cmd, "demo", "scan", "tui", "report", "record", "clean") {
		return errors.New("unknown command; run keyradar help"), false
	}
	var st *casefile.Store
	var c *model.Case
	var e error
	if *path != "" {
		st, e = casefile.Open(*path, model.In(cmd, "scan", "demo", "tui"))
		if e != nil {
			return e, false
		}
		defer st.Close()
		c, e = st.Load()
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e, false
		}
		if errors.Is(e, os.ErrNotExist) && !model.In(cmd, "scan", "demo", "tui") {
			return errors.New("case does not exist"), false
		}
	}
	if c == nil {
		c = model.New(*incident, time.Now())
	}
	switch cmd {
	case "demo":
		if *scenario != "vercel-apr-2026" {
			return errors.New("unknown demo scenario"), false
		}
		if len(c.Runs) > 0 {
			return errors.New("demo requires a new case"), false
		}
		c = scan.Demo()
	case "scan":
		sc, e := sel.scopes()
		if e != nil {
			return e, false
		}
		sc, e = scan.CanonicalScopes(sc)
		if e != nil {
			return e, false
		}
		if len(c.Scopes) > 0 && !scan.SameScopes(c.Scopes, sc) {
			return errors.New("scope differs from case"), false
		}
		tokens, e := PromptTokens(sc)
		if e != nil {
			return e, false
		}
		e = scan.New().Scan(ctx, c, scan.Options{Scopes: sc, Tokens: tokens, RailwayProjectToken: sel.railwayProjectToken}, nil)
		if e != nil {
			return e, false
		}
	case "tui":
		if ui == nil {
			return errors.New("TUI unavailable"), false
		}
		sc, e := sel.scopes()
		if e != nil {
			return e, false
		}
		return ui(ctx, c, st, sc), false
	case "record":
		if st == nil {
			return errors.New("record requires --case"), false
		}
		if e = RecordInteractive(c); e != nil {
			return e, false
		}
	case "clean":
		if st == nil {
			return errors.New("clean requires --case"), false
		}
		for _, a := range c.ToolAccess {
			fmt.Fprintf(out, "Tool access %s / %s: %s\n", a.ID, a.Provider, a.Cleanup)
		}
		if e = st.Clean(*forget); e != nil {
			return e, false
		}
		fmt.Fprintln(out, "Local case removed. Remote credentials and backups are unchanged.")
		return nil, false
	case "report":
		if st == nil {
			return errors.New("report requires --case"), false
		}
	}
	if st != nil && cmd != "report" {
		if e = st.Save(c); e != nil {
			return e, false
		}
	}
	e = report.Write(out, c, *format, *share)
	r, _ := report.Build(c, *share)
	return e, r.CoverageStatus == "partial"
}
func check(ctx context.Context, args []string, out io.Writer) (error, bool) {
	f := flags("issuer check")
	path := f.String("case", "", "case directory")
	provider := f.String("issuer", "", "aws or openai")
	profile := f.String("aws-profile", "", "explicit static profile")
	format := f.String("format", "markdown", "format")
	share := f.Bool("shareable", false, "shareable report")
	var ids stringsFlag
	f.Var(&ids, "credential", "credential ID (repeatable)")
	if e := parse(f, args); e != nil {
		return e, false
	}
	if !model.In(*provider, "aws", "openai") || len(ids) == 0 || !model.In(*format, "markdown", "json") {
		return errors.New("issuer, credential and valid format required"), false
	}
	st, e := casefile.Open(*path, false)
	if e != nil {
		return e, false
	}
	defer st.Close()
	c, e := st.Load()
	if e != nil {
		return e, false
	}
	for _, id := range ids {
		if c.Credential(id) == nil {
			return errors.New("credential not found"), false
		}
	}
	x := issuer.New()
	var token secure.Token
	if *provider == "aws" {
		x, e = issuer.StaticProfile(ctx, *profile)
	} else {
		token, e = PromptToken("OpenAI project-key audit credential")
	}
	if e != nil {
		return e, false
	}
	start := len(c.IssuerObservations)
	if e = x.Check(ctx, c, ids, *provider, token); e != nil {
		return e, false
	}
	if e = st.Save(c); e != nil {
		return e, false
	}
	partial := false
	for _, o := range c.IssuerObservations[start:] {
		if o.Status != "complete" {
			partial = true
		}
	}
	return report.Write(out, c, *format, *share), partial
}
func RecordInteractive(c *model.Case) error {
	action, e := PromptLine("Action: historical, promote, bind, replace, task, activity, cleanup, close")
	if e != nil {
		return e
	}
	now := time.Now().UTC()
	ask := func(label string) string {
		if e != nil {
			return ""
		}
		var v string
		v, e = PromptLine(label)
		return v
	}
	switch action {
	case "historical":
		c.AddCredential(true, "unknown")
	case "promote":
		id := ask("Location ID")
		if e != nil {
			return e
		}
		found := false
		for _, l := range c.Locations {
			if l.ID == id {
				found = true
			}
		}
		if !found {
			return errors.New("location not found")
		}
		cr := c.AddCredential(false, "unknown")
		for i := len(c.Observations) - 1; i >= 0; i-- {
			if c.Observations[i].LocationID == id {
				o := c.Observations[i]
				o.ID = model.ID("obs")
				o.CredentialID = cr
				o.Identity = "operator_assertion"
				o.ObservedAt = now
				c.Observations = append(c.Observations, o)
				break
			}
		}
		c.AddTask(cr, id, "update_configuration")
		c.AddTask(cr, id, "review_history")
		c.AddTask(cr, id, "replace_or_retire_deployments")
		c.AddTask(cr, id, "check_health")
	case "bind":
		id := ask("Credential ID")
		provider := ask("Issuer: aws, openai, stripe, postgres")
		kind := ask("Kind: iam_access_key, project_api_key, api_key, password")
		account := ask("Issuer account/organization ID (not a secret)")
		project := ask("Issuer project ID (blank if not applicable)")
		key := ask("Issuer-native key ID (not a secret value)")
		if e != nil {
			return e
		}
		return app.Bind(c, id, provider, account, project, key, kind, now)
	case "replace":
		old := ask("Old credential ID")
		newID := ask("Replacement credential ID, or new")
		if e != nil {
			return e
		}
		if newID == "new" {
			newID = c.AddCredential(false, "unknown")
		}
		return app.Link(c, old, newID, now)
	case "task":
		id := ask("Task ID")
		status := ask("Status: attested, blocked, accepted_exception, pending")
		if e != nil {
			return e
		}
		return app.Record(c, id, status, now)
	case "activity":
		id := ask("Credential ID")
		stamp := ask("Last-used UTC RFC3339, or blank for unknown")
		if e != nil {
			return e
		}
		var last *time.Time
		if stamp != "" {
			v, err := time.Parse(time.RFC3339, stamp)
			if err != nil {
				return errors.New("invalid activity time")
			}
			last = &v
		}
		return app.ManualActivity(c, id, last, now)
	case "cleanup":
		id := ask("Tool-access ID")
		status := ask("Cleanup: attested or retained_by_operator")
		if e != nil {
			return e
		}
		if !model.In(status, "attested", "retained_by_operator") {
			return errors.New("invalid cleanup status")
		}
		for i := range c.ToolAccess {
			if c.ToolAccess[i].ID == id {
				c.ToolAccess[i].Cleanup = status
				c.UpdatedAt = now
				c.Events = append(c.Events, model.Event{ID: model.ID("event"), TargetID: id, Action: "cleanup_tool_access", Source: "operator_attestation", Result: status, ObservedAt: now})
				return nil
			}
		}
		return errors.New("tool access not found")
	case "close":
		return app.Close(c, now)
	default:
		return errors.New("unknown record action")
	}
	c.UpdatedAt = now
	c.Disposition = "open"
	return e
}
