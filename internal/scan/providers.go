package scan

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
)

type vercelEnv struct {
	ID        string   `json:"id"`
	Key       string   `json:"key"`
	Type      string   `json:"type"`
	Target    []string `json:"target"`
	GitBranch string   `json:"gitBranch"`
	Value     *string  `json:"value"`
	Decrypted bool     `json:"decrypted"`
	UpdatedAt int64    `json:"updatedAt"`
}

func (r *Runner) vercel(ctx context.Context, col *collection, s model.Scope, t secure.Token, run string) {
	if t.Reveal() == "" {
		col.cover(s, "permission_denied", "permission_denied", 0)
		return
	}
	q := url.Values{"teamId": {s.Team}, "decrypt": {"false"}}
	endpoint := "https://api.vercel.com/v10/projects/" + url.PathEscape(s.Project) + "/env?" + q.Encode()
	var list struct {
		Envs []vercelEnv `json:"envs"`
	}
	reason := r.request(ctx, col, "GET", endpoint, nil, header(t, run), &list)
	if reason != "ok" {
		col.cover(s, status(reason), reason, 0)
		return
	}
	if list.Envs == nil {
		col.cover(s, "partial", "invalid_response", 0)
		return
	}
	count := 0
	seen := map[string]bool{}
	for _, v := range list.Envs {
		selected := false
		for _, target := range v.Target {
			if target == s.Environment {
				selected = true
			}
		}
		if !selected {
			continue
		}
		if !validIdent(v.ID) || v.Key == "" || seen[v.ID] {
			col.cover(s, "partial", "invalid_response", 0)
			continue
		}
		seen[v.ID] = true
		if col.limited || ctx.Err() != nil {
			col.cover(s, "partial", "limit_reached", count)
			return
		}
		scope := s
		locator := v.ID + "/" + s.Environment + "/" + v.GitBranch
		i := item{scope: scope, locator: locator, name: v.Key, readability: "unavailable", providerType: v.Type}
		if v.UpdatedAt > 0 {
			i.updated = strconv.FormatInt(v.UpdatedAt, 10)
		}
		switch v.Type {
		case "sensitive", "secret":
			i.readability = "write_only"
		case "plain", "encrypted":
			if v.ID == "" {
				col.cover(s, "partial", "invalid_response", 0)
				continue
			}
			var one vercelEnv
			route := "https://api.vercel.com/v1/projects/" + url.PathEscape(s.Project) + "/env/" + url.PathEscape(v.ID) + "?teamId=" + url.QueryEscape(s.Team)
			why := r.request(ctx, col, "GET", route, nil, header(t, run), &one)
			if why != "ok" {
				i.readability = "denied"
				col.cover(s, status(why), why, 0)
			} else if one.ID == v.ID && one.Key == v.Key && one.Value != nil && one.Decrypted {
				i.readability = "readable"
				i.value = []byte(*one.Value)
			} else if one.ID == v.ID && one.Key == v.Key && one.Type == "plain" && one.Value != nil {
				i.readability = "readable"
				i.value = []byte(*one.Value)
			} else {
				col.cover(s, "partial", "unreadable", 0)
			}
		default:
			i.readability = "unknown_type"
			col.cover(s, "partial", "unknown_type", 0)
		}
		col.add(i)
		count++
	}
	col.cover(s, "complete", "ok", count)
	col.cover(s, "not_checked", "deployment_inventory_unchecked", 0)
	col.cover(s, "not_checked", "shared_inventory_unchecked", 0)
}
func (r *Runner) github(ctx context.Context, col *collection, s model.Scope, t secure.Token, run string) {
	if t.Reveal() == "" {
		col.cover(s, "permission_denied", "permission_denied", 0)
		return
	}
	path := "https://api.github.com/repos/" + s.Project
	if s.Environment == "" {
		path += "/actions/secrets"
	} else {
		path += "/environments/" + url.PathEscape(s.Environment) + "/secrets"
	}
	h := header(t, run)
	h["Accept"] = "application/vnd.github+json"
	h["X-GitHub-Api-Version"] = "2026-03-10"
	count := 0
	seen := map[string]bool{}
	for page := 1; page <= 20; page++ {
		var out struct {
			Total   *int `json:"total_count"`
			Secrets []struct {
				Name      string `json:"name"`
				UpdatedAt string `json:"updated_at"`
			} `json:"secrets"`
		}
		why := r.request(ctx, col, "GET", path+"?per_page=100&page="+strconv.Itoa(page), nil, h, &out)
		if why != "ok" {
			col.cover(s, status(why), why, count)
			return
		}
		if out.Total == nil || *out.Total < 0 || out.Secrets == nil {
			col.cover(s, "partial", "invalid_response", count)
			return
		}
		for _, v := range out.Secrets {
			if v.Name == "" || seen[v.Name] {
				col.cover(s, "partial", "invalid_response", count)
				return
			}
			seen[v.Name] = true
			col.add(item{scope: s, locator: v.Name, name: v.Name, readability: "write_only", providerType: "actions_secret", updated: v.UpdatedAt})
			count++
		}
		if count >= *out.Total {
			col.cover(s, "complete", "ok", count)
			col.cover(s, "not_checked", "organization_secrets_unchecked", 0)
			col.cover(s, "not_checked", "workflow_references_unchecked", 0)
			return
		}
		if len(out.Secrets) == 0 || col.limited {
			col.cover(s, "partial", "limit_reached", count)
			return
		}
	}
	col.cover(s, "partial", "limit_reached", count)
}

const railwayQuery = `query KeyRadarVariables($projectId: String!, $environmentId: String!, $serviceId: String) { variables(projectId: $projectId, environmentId: $environmentId, serviceId: $serviceId, unrendered: true) }`

func (r *Runner) railway(ctx context.Context, col *collection, s model.Scope, t secure.Token, projectToken bool, run string) {
	if t.Reveal() == "" {
		col.cover(s, "permission_denied", "permission_denied", 0)
		return
	}
	h := header(t, run)
	if projectToken {
		delete(h, "Authorization")
		h["Project-Access-Token"] = t.Reveal()
	}
	payload := map[string]any{"query": railwayQuery, "variables": map[string]string{"projectId": s.Project, "environmentId": s.Environment, "serviceId": s.Service}}
	var out struct {
		Data struct {
			Variables map[string]*string `json:"variables"`
		} `json:"data"`
		Errors []struct{} `json:"errors"`
	}
	why := r.request(ctx, col, "POST", "https://backboard.railway.com/graphql/v2", payload, h, &out)
	if why != "ok" {
		col.cover(s, status(why), why, 0)
		return
	}
	if len(out.Errors) > 0 {
		col.cover(s, "partial", "request_failed", 0)
	}
	if out.Data.Variables == nil {
		col.cover(s, "partial", "scope_unavailable", 0)
		return
	}
	names := make([]string, 0, len(out.Data.Variables))
	for n := range out.Data.Variables {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v := out.Data.Variables[n]
		i := item{scope: s, locator: n, name: n, readability: "unavailable", providerType: "railway_variable"}
		if v != nil {
			if strings.Contains(*v, "${{") {
				i.reference = "unresolved"
				i.providerType = "reference"
				col.cover(s, "partial", "references_unresolved", 0)
			} else {
				i.readability = "readable"
				i.value = []byte(*v)
			}
		}
		col.add(i)
	}
	col.cover(s, "complete", "ok", len(names))
	col.cover(s, "not_checked", "sealed_inventory_unknown", 0)
	col.cover(s, "not_checked", "shared_inventory_unchecked", 0)
	col.cover(s, "not_checked", "deployment_inventory_unchecked", 0)
}
