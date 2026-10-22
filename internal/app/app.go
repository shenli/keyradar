// Package app contains operations shared by the CLI and TUI. No remote writes exist.
package app

import (
	"errors"
	"strings"
	"time"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
)

func Record(c *model.Case, target, status string, now time.Time) error {
	if !model.In(status, "attested", "blocked", "accepted_exception", "pending") {
		return errors.New("invalid human task status")
	}
	for i := range c.Tasks {
		t := &c.Tasks[i]
		if t.ID == target {
			t.Status = status
			c.Events = append(c.Events, model.Event{ID: model.ID("event"), TargetID: target, Action: t.Action, Source: "operator_attestation", Result: status, ObservedAt: now.UTC()})
			c.UpdatedAt = now.UTC()
			c.Disposition = "open"
			return nil
		}
	}
	return errors.New("task not found")
}
func Bind(c *model.Case, id, provider, account, project, key, kind string, now time.Time) error {
	cr := c.Credential(id)
	if cr == nil {
		return errors.New("credential not found")
	}
	if !model.In(provider, "aws", "openai", "stripe", "postgres") || !model.In(kind, "iam_access_key", "project_api_key", "api_key", "password") {
		return errors.New("invalid issuer or credential class")
	}
	for _, s := range []string{account, project, key} {
		if len(s) > 256 || secure.Text(s) != s {
			return errors.New("invalid identifier")
		}
	}
	for _, prefix := range []string{"sk-", "sk_", "rk_", "ghp_", "github_pat_"} {
		if strings.HasPrefix(key, prefix) {
			return errors.New("enter an issuer key identifier, never the secret value")
		}
	}
	// Evidence for an old issuer binding remains immutable; do not rebind an existing record.
	if cr.KeyID != "" && (cr.KeyID != key || cr.Account != account || cr.Project != project || cr.Issuer != provider) {
		return errors.New("create a new credential for a different issuer binding")
	}
	cr.Issuer = provider
	cr.Account = account
	cr.Project = project
	cr.KeyID = key
	cr.Kind = kind
	cr.Binding = "operator_assertion"
	c.Events = append(c.Events, model.Event{ID: model.ID("event"), TargetID: id, Action: "bind_issuer", Source: "operator_attestation", ObservedAt: now.UTC()})
	c.UpdatedAt = now.UTC()
	c.Disposition = "open"
	return nil
}
func Link(c *model.Case, old, new string, now time.Time) error {
	a := c.Credential(old)
	if a == nil || c.Credential(new) == nil || old == new {
		return errors.New("invalid replacement link")
	}
	seen := map[string]bool{}
	var reaches func(string) bool
	reaches = func(id string) bool {
		if id == old {
			return true
		}
		if seen[id] {
			return false
		}
		seen[id] = true
		v := c.Credential(id)
		for _, n := range v.ReplacementIDs {
			if reaches(n) {
				return true
			}
		}
		return false
	}
	if reaches(new) {
		return errors.New("replacement cycle rejected")
	}
	for _, id := range a.ReplacementIDs {
		if id == new {
			return nil
		}
	}
	a.ReplacementIDs = append(a.ReplacementIDs, new)
	c.Events = append(c.Events, model.Event{ID: model.ID("event"), TargetID: old, Action: "link_replacement", Source: "operator_attestation", ObservedAt: now.UTC()})
	c.UpdatedAt = now.UTC()
	c.Disposition = "open"
	return nil
}
func Close(c *model.Case, now time.Time) error {
	for _, t := range c.Tasks {
		if t.Status == "pending" || t.Status == "blocked" {
			return errors.New("resolve or explicitly accept outstanding tasks before closure")
		}
	}
	c.Disposition = "closed_by_operator"
	c.UpdatedAt = now.UTC()
	c.Events = append(c.Events, model.Event{ID: model.ID("event"), TargetID: c.ID, Action: "close_case", Source: "operator_attestation", Result: "closed_by_operator", ObservedAt: now.UTC()})
	return nil
}
func ManualActivity(c *model.Case, id string, last *time.Time, now time.Time) error {
	cr := c.Credential(id)
	if cr == nil {
		return errors.New("credential not found")
	}
	if last != nil && last.After(now) {
		return errors.New("future activity rejected")
	}
	a := "insufficient_evidence"
	if last != nil {
		a = "usage_observed"
	}
	c.IssuerObservations = append(c.IssuerObservations, model.IssuerObservation{ID: model.ID("evidence"), CredentialID: id, Issuer: cr.Issuer, Source: "operator_attestation", FetchedAt: now.UTC(), LastUsedAt: last, Status: "complete", Reason: "operator_reported", Activity: a, Freshness: "unknown", Binding: cr.Binding, Account: cr.Account, Project: cr.Project, KeyID: cr.KeyID})
	c.UpdatedAt = now.UTC()
	c.Disposition = "open"
	return nil
}
