// Package scan owns all transient source values. Only metadata leaves this package.
package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
	"github.com/shenli/keyradar/templates"
)

const maxItems = 2000
const maxMaterial = 8 << 20

var ident = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
var keyName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validIdent(s string) bool { return s != "." && s != ".." && ident.MatchString(s) }

type Options struct {
	Scopes              []model.Scope
	Tokens              map[string]secure.Token
	RailwayProjectToken bool
}
type Progress struct {
	Source string
	Status string
}
type Runner struct {
	client *http.Client
	now    func() time.Time
}

func New() *Runner { return &Runner{client: secure.HTTPClient(), now: time.Now} }

type item struct {
	scope                                                        model.Scope
	locator, name, readability, providerType, updated, reference string
	value                                                        []byte
}

func (item) String() string   { return "[source observation]" }
func (item) GoString() string { return "[source observation]" }

type collection struct {
	items           []item
	coverage        []model.Coverage
	bytes, requests int
	limited         bool
}

func (c *collection) add(i item) {
	if len(c.items) >= maxItems || len(i.value) > 64<<10 || c.bytes+len(i.value) > maxMaterial {
		c.limited = true
		return
	}
	c.bytes += len(i.value)
	c.items = append(c.items, i)
}
func (c *collection) cover(s model.Scope, status, reason string, n int) {
	c.coverage = append(c.coverage, model.Coverage{Scope: s, Status: status, Reason: reason, Count: n})
}
func ValidateScopes(scopes []model.Scope) error {
	if len(scopes) == 0 || len(scopes) > 100 {
		return errors.New("select between 1 and 100 source scopes")
	}
	files := 0
	seen := map[string]bool{}
	for _, s := range scopes {
		if !model.ValidScope(s) || seen[s.Key()] {
			return errors.New("invalid or duplicate source scope")
		}
		seen[s.Key()] = true
		switch s.Source {
		case "local":
			files++
			if s.File == "" || len(s.File) > 4096 {
				return errors.New("invalid file selection")
			}
		case "vercel":
			if !validIdent(s.Project) || !validIdent(s.Team) || !model.In(s.Environment, "production", "preview", "development") {
				return errors.New("Vercel requires team, project and production/preview/development")
			}
		case "railway":
			if !validIdent(s.Project) || !validIdent(s.Environment) || !validIdent(s.Service) {
				return errors.New("Railway requires project, environment and service")
			}
		case "github":
			p := strings.Split(s.Project, "/")
			if len(p) != 2 || !validIdent(p[0]) || !validIdent(p[1]) || model.In(s.Environment, ".", "..") || len(s.Environment) > 200 || strings.ContainsAny(s.Environment, "\x00\r\n") {
				return errors.New("GitHub requires owner/repository and an optional environment")
			}
		}
	}
	if files > 50 {
		return errors.New("file selection limit exceeded")
	}
	return nil
}
func CanonicalScopes(scopes []model.Scope) ([]model.Scope, error) {
	out := append([]model.Scope(nil), scopes...)
	for i := range out {
		if out[i].Source == "local" {
			p, e := filepath.Abs(out[i].File)
			if e != nil {
				return nil, errors.New("invalid file selection")
			}
			out[i].File = p
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, ValidateScopes(out)
}
func SameScopes(a, b []model.Scope) bool {
	if len(a) != len(b) {
		return false
	}
	x := make([]string, len(a))
	y := make([]string, len(b))
	for i := range a {
		x[i] = a[i].Key()
		y[i] = b[i].Key()
	}
	sort.Strings(x)
	sort.Strings(y)
	return strings.Join(x, "\n") == strings.Join(y, "\n")
}
func (r *Runner) Scan(ctx context.Context, c *model.Case, opt Options, progress func(Progress)) error {
	scopes, e := CanonicalScopes(opt.Scopes)
	if e != nil {
		return e
	}
	if len(c.Scopes) > 0 && !SameScopes(c.Scopes, scopes) {
		return errors.New("scope differs from case; create a new case for changed authorization")
	}
	run := model.Run{ID: model.ID("run"), StartedAt: r.now().UTC(), ToolVersion: model.Version}
	col := &collection{}
	registered := map[string]bool{}
	for _, s := range scopes {
		if s.Source != "local" && !registered[s.Source] {
			authID := model.ID("auth")
			c.ToolAccess = append(c.ToolAccess, model.ToolAccess{ID: authID, Provider: s.Source, StartedAt: run.StartedAt, Cleanup: "pending"})
			run.AccessIDs = append(run.AccessIDs, authID)
			registered[s.Source] = true
		}
		if progress != nil {
			progress(Progress{Source: s.Source, Status: "collecting"})
		}
		if ctx.Err() != nil {
			col.cover(s, "partial", "cancelled", 0)
			continue
		}
		if col.limited {
			col.cover(s, "partial", "limit_reached", 0)
			continue
		}
		switch s.Source {
		case "local":
			r.local(col, s)
		case "vercel":
			r.vercel(ctx, col, s, opt.Tokens[s.Source], run.ID)
		case "github":
			r.github(ctx, col, s, opt.Tokens[s.Source], run.ID)
		case "railway":
			r.railway(ctx, col, s, opt.Tokens[s.Source], opt.RailwayProjectToken, run.ID)
		}
		if col.limited {
			col.cover(s, "partial", "limit_reached", 0)
		}
		if progress != nil {
			progress(Progress{Source: s.Source, Status: "collected"})
		}
	}
	c.Scopes = scopes
	r.finish(c, col, run)
	// Remove known source/auth material from ALL metadata, including provider names and error-adjacent fields.
	scrubCase(c, col, opt.Tokens)
	for i := range col.items {
		clear(col.items[i].value)
	}
	return c.Validate()
}
func candidate(i item) bool {
	n := strings.ToUpper(i.name)
	for _, p := range []string{"SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY", "DATABASE_URL", "CONNECTION_STRING", "CREDENTIAL"} {
		if strings.Contains(n, p) {
			return true
		}
	}
	v := string(i.value)
	return strings.HasPrefix(v, "sk-") || strings.HasPrefix(v, "sk_live_") || strings.HasPrefix(v, "rk_live_") || strings.HasPrefix(v, "ghp_")
}
func (r *Runner) finish(c *model.Case, col *collection, run model.Run) {
	run.FinishedAt = r.now().UTC()
	run.Requests = col.requests
	run.Coverage = col.coverage
	c.Runs = append(c.Runs, run)
	c.UpdatedAt = run.FinishedAt
	c.Disposition = "open"
	groups := map[int][]int{}
	credFor := map[int]string{}
	for n, i := range col.items {
		lid := ""
		for _, l := range c.Locations {
			if l.Scope.Key() == i.scope.Key() && l.Locator == i.locator {
				lid = l.ID
				break
			}
		}
		if lid == "" {
			lid = model.ID("loc")
			c.Locations = append(c.Locations, model.Location{ID: lid, Scope: i.scope, Locator: i.locator, Variable: i.name})
		}
		o := model.Observation{ID: model.ID("obs"), RunID: run.ID, LocationID: lid, ObservedAt: run.FinishedAt, Readability: i.readability, ProviderType: i.providerType, ProviderUpdatedAt: i.updated, Identity: "unknown"}
		if i.reference != "" {
			o.Identity = "provider_reference"
		}
		if candidate(i) {
			rep := n
			if i.readability == "readable" && len(i.value) > 0 && i.reference == "" && !strings.Contains(strings.ToUpper(i.name), "PASSWORD") && !strings.Contains(strings.ToUpper(i.name), "PASSWD") {
				for _, j := range groups[len(i.value)] {
					if bytes.Equal(i.value, col.items[j].value) {
						rep = j
						break
					}
				}
				if rep == n {
					groups[len(i.value)] = append(groups[len(i.value)], n)
				}
			}
			cid := credFor[rep]
			if cid == "" {
				cid = c.AddCredential(false, "unknown")
				credFor[rep] = cid
			}
			if exposure := templates.Exposure(c.Incident, i.scope.Source, i.readability); exposure != "unknown" {
				c.Credential(cid).Exposure = exposure
			}
			o.CredentialID = cid
			if i.readability == "readable" && len(i.value) > 0 && i.reference == "" {
				o.Identity = "equal_value"
			}
			for _, a := range []string{"update_configuration", "check_health", "review_history"} {
				c.AddTask(cid, lid, a)
			}
			if i.scope.Source != "local" {
				c.AddTask(cid, lid, "replace_or_retire_deployments")
			}
		} else {
			c.AddTask("", lid, "review_classification")
		}
		c.Observations = append(c.Observations, o)
	}
	for _, v := range col.coverage {
		if v.Status != "complete" {
			c.AddTask("", "", "review_unchecked_scope")
		}
	}
	if len(c.ToolAccess) > 0 {
		c.AddTask("", "", "cleanup_tool_access")
	}
}
func scrubCase(c *model.Case, col *collection, tokens map[string]secure.Token) {
	// JSON string leaf traversal preserves schema vocabulary and timestamps; scrub only metadata labels.
	secrets := []string{}
	for _, i := range col.items {
		if len(i.value) > 0 {
			secrets = append(secrets, string(i.value))
		}
	}
	for _, t := range tokens {
		if t.Reveal() != "" {
			secrets = append(secrets, t.Reveal())
		}
	}
	clean := func(s string) string {
		for _, v := range secrets {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
		return secure.Text(s)
	}
	scope := func(s *model.Scope) {
		s.Project = clean(s.Project)
		s.Team = clean(s.Team)
		s.Service = clean(s.Service)
		s.Environment = clean(s.Environment)
		s.File = clean(s.File)
	}
	for i := range c.Scopes {
		scope(&c.Scopes[i])
	}
	for i := range c.Locations {
		l := &c.Locations[i]
		scope(&l.Scope)
		l.Locator = clean(l.Locator)
		l.Variable = clean(l.Variable)
	}
	for i := range c.Runs {
		for j := range c.Runs[i].Coverage {
			scope(&c.Runs[i].Coverage[j].Scope)
		}
	}
	for i := range c.Observations {
		o := &c.Observations[i]
		o.ProviderType = clean(o.ProviderType)
		o.ProviderUpdatedAt = clean(o.ProviderUpdatedAt)
	}
}
func (r *Runner) request(ctx context.Context, col *collection, method, endpoint string, body any, headers map[string]string, out any) string {
	var data io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		data = bytes.NewReader(b)
	}
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return "cancelled"
		}
		u, e := url.Parse(endpoint)
		if e != nil || u.Scheme != "https" || !model.In(u.Host, "api.vercel.com", "api.github.com", "backboard.railway.com") {
			return "request_failed"
		}
		req, e := http.NewRequestWithContext(ctx, method, endpoint, data)
		if e != nil {
			return "request_failed"
		}
		// Recreate body on retry; payload is a fixed GraphQL read query, never a source value.
		if body != nil {
			b, _ := json.Marshal(body)
			req.Body = io.NopCloser(bytes.NewReader(b))
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		col.requests++
		resp, e := r.client.Do(req)
		if e != nil {
			if ctx.Err() != nil {
				return "cancelled"
			}
			return "request_failed"
		}
		code := resp.StatusCode
		if code == 429 || code >= 500 {
			resp.Body.Close()
			if attempt == 2 {
				if code == 429 {
					return "rate_limited"
				}
				return "request_failed"
			}
			wait := time.Duration(attempt+1) * 200 * time.Millisecond
			if retry := resp.Header.Get("Retry-After"); retry != "" {
				if seconds, err := strconv.Atoi(retry); err == nil && seconds >= 0 {
					if seconds > 5 {
						return "rate_limited"
					}
					wait = max(wait, time.Duration(seconds)*time.Second)
				} else if when, err := http.ParseTime(retry); err == nil {
					delay := when.Sub(r.now())
					if delay > 5*time.Second {
						return "rate_limited"
					}
					wait = max(wait, delay)
				}
			}
			select {
			case <-ctx.Done():
				return "cancelled"
			case <-time.After(wait):
			}
			continue
		}
		if code != 200 {
			resp.Body.Close()
			switch code {
			case 401, 403:
				return "permission_denied"
			case 404:
				return "not_found"
			default:
				return "request_failed"
			}
		}
		e = secure.Decode(resp.Body, 4<<20, out)
		resp.Body.Close()
		if e != nil {
			return "invalid_response"
		}
		return "ok"
	}
	return "request_failed"
}
func status(reason string) string {
	switch reason {
	case "ok":
		return "complete"
	case "permission_denied", "rate_limited":
		return reason
	default:
		return "partial"
	}
}
func header(token secure.Token, run string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token.Reveal(), "User-Agent": "KeyRadar/" + model.Version + " " + run, "Content-Type": "application/json"}
}
func (r *Runner) local(col *collection, s model.Scope) {
	b, e := secure.ReadFile(s.File, 1<<20)
	if e != nil {
		col.cover(s, "partial", "unreadable", 0)
		return
	}
	defer clear(b)
	vars, warn := parseEnv(b)
	names := make([]string, 0, len(vars))
	for n := range vars {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		col.add(item{scope: s, locator: n, name: n, readability: "readable", providerType: "dotenv", value: vars[n]})
	}
	if warn {
		col.cover(s, "partial", "parse_warning", len(names))
	} else {
		col.cover(s, "complete", "ok", len(names))
	}
}
func parseEnv(b []byte) (map[string][]byte, bool) {
	out := map[string][]byte{}
	seen := map[string]bool{}
	bad := map[string]bool{}
	warn := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !keyName.MatchString(k) {
			warn = true
			continue
		}
		if seen[k] {
			bad[k] = true
			delete(out, k)
			warn = true
			continue
		}
		seen[k] = true
		if strings.ContainsAny(v, "\x00`$") {
			warn = true
			continue
		}
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "\"") || strings.HasPrefix(v, "'") {
			q := v[0]
			if len(v) < 2 || v[len(v)-1] != q {
				warn = true
				continue
			}
			v = v[1 : len(v)-1]
			if strings.ContainsRune(v, rune(q)) || strings.Contains(v, "\\") {
				warn = true
				continue
			}
		}
		if len(v) > 64<<10 {
			warn = true
			continue
		}
		if !bad[k] {
			out[k] = []byte(v)
		}
	}
	return out, warn
}

// No subprocess, environment-variable or CLI-cache authentication discovery is performed here.
