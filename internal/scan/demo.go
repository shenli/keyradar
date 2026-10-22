package scan

import (
	"time"

	"github.com/shenli/keyradar/internal/model"
)

// Demo is entirely offline. The fixture values are never returned or written.
func Demo() *model.Case {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	r := &Runner{now: func() time.Time { return now }}
	c := model.New("vercel-apr-2026", now)
	col := &collection{}
	scopes := []model.Scope{{Source: "vercel", Team: "demo-team", Project: "demo-web", Environment: "production"}, {Source: "railway", Project: "demo-worker", Environment: "production", Service: "worker"}, {Source: "local", File: "synthetic/demo.env"}, {Source: "github", Project: "example/demo", Environment: "production"}}
	for _, s := range scopes {
		c.Scopes = append(c.Scopes, s)
		i := item{scope: s, locator: "demo-key", name: "OPENAI_API_KEY", readability: "readable", providerType: "synthetic", value: []byte("KEYRADAR_SYNTHETIC_NEVER_VALID_27d8d9")}
		if s.Source == "github" {
			i.value = nil
			i.readability = "write_only"
		}
		col.add(i)
		col.cover(s, "complete", "ok", 1)
	}
	col.add(item{scope: scopes[0], locator: "staging-key", name: "STRIPE_SECRET_KEY", readability: "write_only", providerType: "sensitive"})
	col.cover(scopes[0], "not_checked", "deployment_inventory_unchecked", 0)
	col.cover(scopes[1], "not_checked", "sealed_inventory_unknown", 0)
	r.finish(c, col, model.Run{ID: model.ID("run"), StartedAt: now, ToolVersion: model.Version})
	old := c.AddCredential(true, "potentially_exposed")
	cred := c.Credential(old)
	cred.Issuer = "aws"
	cred.Kind = "iam_access_key"
	cred.Binding = "operator_assertion"
	cred.Account = "000000000000"
	cred.KeyID = "AKIAEXAMPLEONLY000000"
	used := now.Add(-time.Hour)
	c.IssuerObservations = append(c.IssuerObservations, model.IssuerObservation{ID: model.ID("evidence"), CredentialID: old, Issuer: "aws", Source: "operator_attestation", FetchedAt: now, LastUsedAt: &used, Status: "complete", Reason: "operator_reported", Activity: "usage_observed", Freshness: "unknown", Binding: "operator_assertion"})
	for _, s := range []string{"vercel", "railway", "github"} {
		c.ToolAccess = append(c.ToolAccess, model.ToolAccess{ID: model.ID("auth"), Provider: s, StartedAt: now, Cleanup: "pending"})
	}
	c.AddTask("", "", "cleanup_tool_access")
	for i := range col.items {
		clear(col.items[i].value)
	}
	return c
}
