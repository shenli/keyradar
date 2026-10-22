package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/report"
	"github.com/shenli/keyradar/internal/secure"
)

const canary = "KEYRADAR_CANARY_opaque_53d7b4"

type transport func(*http.Request) (*http.Response, error)

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) { return t(r) }
func response(code int, v any) *http.Response {
	b, _ := json.Marshal(v)
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}
}
func fixedRunner(t *testing.T, fn transport) *Runner {
	t.Helper()
	return &Runner{client: &http.Client{Transport: fn}, now: func() time.Time { return time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC) }}
}
func checkLeak(t *testing.T, c *model.Case, values ...string) {
	t.Helper()
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal("serialization failed")
	}
	for _, v := range values {
		if strings.Contains(string(b), v) {
			t.Fatal("canary leaked in case")
		}
	}
	for _, f := range []string{"json", "markdown"} {
		for _, share := range []bool{false, true} {
			var b strings.Builder
			if report.Write(&b, c, f, share) != nil {
				t.Fatal("report failed")
			}
			for _, v := range values {
				if strings.Contains(b.String(), v) {
					t.Fatal("canary leaked in report")
				}
			}
		}
	}
}
func TestProvidersAndRedaction(t *testing.T) {
	calls := 0
	r := fixedRunner(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != "GET" && req.URL.Host != "backboard.railway.com" {
			t.Fatal("unexpected remote method")
		}
		switch req.URL.Host {
		case "api.vercel.com":
			if strings.HasPrefix(req.URL.Path, "/v10/") {
				return response(200, map[string]any{"envs": []any{map[string]any{"id": "v1", "key": "API_KEY_" + canary, "type": "encrypted", "target": []string{"production"}}, map[string]any{"id": "v2", "key": "STRIPE_SECRET_KEY", "type": "sensitive", "target": []string{"production"}}}}), nil
			}
			if strings.Contains(req.URL.Path, "v2") {
				t.Fatal("attempted sensitive read")
			}
			return response(200, map[string]any{"id": "v1", "key": "API_KEY_" + canary, "type": "encrypted", "decrypted": true, "value": canary}), nil
		case "api.github.com":
			return response(200, map[string]any{"total_count": 1, "secrets": []any{map[string]any{"name": "OPENAI_API_KEY", "updated_at": "2026-10-01T00:00:00Z"}}}), nil
		case "backboard.railway.com":
			body, _ := io.ReadAll(req.Body)
			if strings.Contains(string(body), "mutation") {
				t.Fatal("mutation forbidden")
			}
			return response(200, map[string]any{"data": map[string]any{"variables": map[string]any{"OPENAI_API_KEY": canary, "DATABASE_URL": "${{Postgres.URL}}"}}}), nil
		}
		return nil, fmt.Errorf("unexpected host")
	})
	c := model.New("vercel-apr-2026", r.now())
	sc := []model.Scope{{Source: "vercel", Team: "team", Project: "project", Environment: "production"}, {Source: "github", Project: "org/repo"}, {Source: "railway", Project: "rp", Environment: "re", Service: "rs"}}
	if e := r.Scan(context.Background(), c, Options{Scopes: sc, Tokens: map[string]secure.Token{"vercel": secure.NewToken("auth-canary"), "github": secure.NewToken("auth-canary"), "railway": secure.NewToken("auth-canary")}}, nil); e != nil {
		t.Fatal(e)
	}
	if calls != 4 {
		t.Fatalf("unexpected requests: %d", calls)
	}
	var equalIDs []string
	for _, o := range c.Observations {
		if o.Identity == "equal_value" {
			equalIDs = append(equalIDs, o.CredentialID)
		}
	}
	if len(equalIDs) != 2 || equalIDs[0] != equalIDs[1] {
		t.Fatal("equal readable material did not group")
	}
	for _, o := range c.Observations {
		if o.Readability == "write_only" && o.Identity != "unknown" {
			t.Fatal("write-only identity inferred")
		}
	}
	checkLeak(t, c, canary, "auth-canary")
	b, _ := report.Build(c, true)
	blob, _ := json.Marshal(b)
	if strings.Contains(string(blob), "org/repo") || strings.Contains(string(blob), "Postgres") {
		t.Fatal("private metadata escaped projection")
	}
}
func TestGitHubPartialPagination(t *testing.T) {
	r := fixedRunner(t, func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("page") == "1" {
			return response(200, map[string]any{"total_count": 2, "secrets": []any{map[string]any{"name": "SECRET_KEY"}}}), nil
		}
		return response(403, map[string]any{"error": canary}), nil
	})
	c := model.New("custom", r.now())
	if e := r.Scan(context.Background(), c, Options{Scopes: []model.Scope{{Source: "github", Project: "a/b"}}, Tokens: map[string]secure.Token{"github": secure.NewToken("x")}}, nil); e != nil {
		t.Fatal(e)
	}
	if len(c.Observations) != 1 || c.Runs[0].Coverage[0].Status != "permission_denied" {
		t.Fatal("partial evidence lost")
	}
	checkLeak(t, c, canary)
}
func TestRailwayGraphQLErrorAndNull(t *testing.T) {
	r := fixedRunner(t, func(*http.Request) (*http.Response, error) {
		return response(200, map[string]any{"errors": []any{map[string]any{"message": canary}}, "data": map[string]any{"variables": map[string]any{"API_KEY": nil}}}), nil
	})
	c := model.New("custom", r.now())
	if e := r.Scan(context.Background(), c, Options{Scopes: []model.Scope{{Source: "railway", Project: "a", Environment: "b", Service: "c"}}, Tokens: map[string]secure.Token{"railway": secure.NewToken("token")}}, nil); e != nil {
		t.Fatal(e)
	}
	if c.Observations[0].Readability != "unavailable" {
		t.Fatal("null treated as readable")
	}
	rep, _ := report.Build(c, false)
	if rep.CoverageStatus != "partial" {
		t.Fatal("GraphQL error swallowed")
	}
	checkLeak(t, c, canary)
}
func TestParseEnv(t *testing.T) {
	vars, warn := parseEnv([]byte("API_KEY=' space '\r\nexport TOKEN=abc\nDUP=x\nDUP=y\nBAD=$(touch /tmp/no)\nEMPTY=\n"))
	if !warn || string(vars["API_KEY"]) != " space " || string(vars["TOKEN"]) != "abc" {
		t.Fatal("parser semantics")
	}
	if _, ok := vars["DUP"]; ok {
		t.Fatal("duplicate accepted")
	}
	if _, ok := vars["BAD"]; ok {
		t.Fatal("expansion accepted")
	}
}
func TestLocalRescanPreservesHistoryAndDoesNotProveChange(t *testing.T) {
	dir := t.TempDir()
	real, _ := filepath.EvalSymlinks(dir)
	p := filepath.Join(real, "input.env")
	os.WriteFile(p, []byte("API_KEY="+canary+"\n"), 0600)
	c := model.New("custom", time.Now())
	opt := Options{Scopes: []model.Scope{{Source: "local", File: p}}}
	r := New()
	if e := r.Scan(context.Background(), c, opt, nil); e != nil {
		t.Fatal(e)
	}
	old := c.Credentials[0].ID
	hist := c.AddCredential(true, "potentially_exposed")
	n := len(c.Tasks)
	os.WriteFile(p, []byte("API_KEY=changed-fake-material\n"), 0600)
	if e := r.Scan(context.Background(), c, opt, nil); e != nil {
		t.Fatal(e)
	}
	if c.Credential(hist) == nil || c.Credential(old) == nil || len(c.Tasks) <= n || len(c.Locations) != 1 {
		t.Fatal("rescan lost history or location identity")
	}
	if c.Observations[0].CredentialID == c.Observations[1].CredentialID {
		t.Fatal("cross-run identity guessed")
	}
	for _, task := range c.Tasks {
		if task.Status != "pending" {
			t.Fatal("rescan completed task")
		}
	}
	checkLeak(t, c, canary, "changed-fake-material")
}
func TestNoSymlinkReads(t *testing.T) {
	d, _ := filepath.EvalSymlinks(t.TempDir())
	p := filepath.Join(d, "real")
	os.WriteFile(p, []byte("API_KEY="+canary), 0600)
	os.Symlink(p, filepath.Join(d, "link"))
	c := model.New("custom", time.Now())
	if e := New().Scan(context.Background(), c, Options{Scopes: []model.Scope{{Source: "local", File: filepath.Join(d, "link")}}}, nil); e != nil {
		t.Fatal(e)
	}
	if len(c.Observations) != 0 || c.Runs[0].Coverage[0].Status != "partial" {
		t.Fatal("symlink followed")
	}
}
func TestCancelledScopes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := model.New("custom", time.Now())
	if e := New().Scan(ctx, c, Options{Scopes: []model.Scope{{Source: "github", Project: "a/b"}}}, nil); e != nil {
		t.Fatal(e)
	}
	if c.Runs[0].Coverage[0].Reason != "cancelled" {
		t.Fatal("cancel lost")
	}
}
func TestEncryptedResponseNeverMatches(t *testing.T) {
	r := fixedRunner(t, func(req *http.Request) (*http.Response, error) {
		if strings.HasPrefix(req.URL.Path, "/v10") {
			return response(200, map[string]any{"envs": []any{map[string]any{"id": "id", "key": "API_KEY", "type": "encrypted", "target": []string{"production"}}}}), nil
		}
		return response(200, map[string]any{"id": "id", "key": "API_KEY", "type": "encrypted", "value": canary, "decrypted": false}), nil
	})
	c := model.New("custom", r.now())
	if e := r.Scan(context.Background(), c, Options{Scopes: []model.Scope{{Source: "vercel", Project: "p", Team: "t", Environment: "production"}}, Tokens: map[string]secure.Token{"vercel": secure.NewToken("token")}}, nil); e != nil {
		t.Fatal(e)
	}
	if c.Observations[0].Identity == "equal_value" {
		t.Fatal("encrypted payload compared")
	}
	checkLeak(t, c, canary)
}
func FuzzParseEnv(f *testing.F) {
	f.Add("API_KEY=abc\n")
	f.Add("TOKEN=' value '\n")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			return
		}
		v, _ := parseEnv([]byte(s))
		for k, b := range v {
			if !keyName.MatchString(k) || len(b) > 64<<10 {
				t.Fatal("parser invariant")
			}
		}
	})
}
func TestDemo(t *testing.T) {
	c := Demo()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	checkLeak(t, c, "KEYRADAR_SYNTHETIC_NEVER_VALID_27d8d9")
}

func TestMatchingSeparatesDistinctAndUnscopedPasswords(t *testing.T) {
	r := New()
	c := model.New("custom", time.Now())
	s := model.Scope{Source: "local", File: "synthetic"}
	col := &collection{items: []item{
		{scope: s, locator: "prod", name: "API_KEY", readability: "readable", value: []byte("prod-synthetic")},
		{scope: s, locator: "staging", name: "API_KEY", readability: "readable", value: []byte("staging-synthetic")},
		{scope: s, locator: "copy", name: "TOKEN", readability: "readable", value: []byte("prod-synthetic")},
		{scope: s, locator: "password-a", name: "PASSWORD", readability: "readable", value: []byte("same-password")},
		{scope: s, locator: "password-b", name: "PASSWORD", readability: "readable", value: []byte("same-password")},
		{scope: s, locator: "empty-a", name: "TOKEN", readability: "readable"},
		{scope: s, locator: "empty-b", name: "TOKEN", readability: "readable"},
	}}
	r.finish(c, col, model.Run{ID: model.ID("run"), StartedAt: r.now()})
	o := c.Observations
	if o[0].CredentialID != o[2].CredentialID || o[0].CredentialID == o[1].CredentialID || o[3].CredentialID == o[4].CredentialID || o[5].CredentialID == o[6].CredentialID || o[5].Identity != "unknown" {
		t.Fatal("unsafe equality inference")
	}
}

func TestRetryAfterStopsInsteadOfIgnoringLongBackoff(t *testing.T) {
	calls := 0
	r := fixedRunner(t, func(*http.Request) (*http.Response, error) {
		calls++
		resp := response(429, map[string]string{"error": canary})
		resp.Header.Set("Retry-After", "120")
		return resp, nil
	})
	col := &collection{}
	var out any
	reason := r.request(context.Background(), col, "GET", "https://api.github.com/repos/a/b/actions/secrets", nil, nil, &out)
	if reason != "rate_limited" || calls != 1 {
		t.Fatal("unbounded or early retry")
	}
}

func TestScopeRejectsDotSegments(t *testing.T) {
	for _, s := range []model.Scope{{Source: "github", Project: "../repo"}, {Source: "vercel", Project: "..", Team: "team", Environment: "production"}, {Source: "github", Project: "owner/repo", Environment: ".."}} {
		if ValidateScopes([]model.Scope{s}) == nil {
			t.Fatal("dot segment accepted")
		}
	}
}
