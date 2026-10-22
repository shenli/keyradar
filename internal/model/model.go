// Package model contains only metadata. Credential material must never enter these types.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

const SchemaVersion = 1
const Version = "0.1.0-alpha"

type Scope struct {
	Source      string `json:"source"`
	Project     string `json:"project,omitempty"`
	Environment string `json:"environment,omitempty"`
	Service     string `json:"service,omitempty"`
	Team        string `json:"team,omitempty"`
	File        string `json:"file,omitempty"`
}

func (s Scope) Key() string {
	return fmt.Sprintf("%q/%q/%q/%q/%q/%q", s.Source, s.Team, s.Project, s.Environment, s.Service, s.File)
}

type Coverage struct {
	Scope  Scope  `json:"scope"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}
type Run struct {
	ID          string     `json:"id"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
	ToolVersion string     `json:"tool_version"`
	Coverage    []Coverage `json:"coverage"`
	Requests    int        `json:"requests"`
	AccessIDs   []string   `json:"access_ids,omitempty"`
}
type Location struct {
	ID       string `json:"id"`
	Scope    Scope  `json:"scope"`
	Locator  string `json:"locator"`
	Variable string `json:"variable"`
}
type Observation struct {
	ID                string    `json:"id"`
	RunID             string    `json:"run_id"`
	LocationID        string    `json:"location_id"`
	CredentialID      string    `json:"credential_id,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	Readability       string    `json:"readability"`
	ProviderType      string    `json:"provider_type,omitempty"`
	ProviderUpdatedAt string    `json:"provider_updated_at,omitempty"`
	Identity          string    `json:"identity"`
}
type Credential struct {
	ID             string   `json:"id"`
	Issuer         string   `json:"issuer"`
	Account        string   `json:"account,omitempty"`
	Project        string   `json:"project,omitempty"`
	KeyID          string   `json:"key_id,omitempty"`
	Kind           string   `json:"kind"`
	Binding        string   `json:"binding"`
	Historical     bool     `json:"historical"`
	Exposure       string   `json:"exposure"`
	ReplacementIDs []string `json:"replacement_ids,omitempty"`
}
type Task struct {
	ID           string `json:"id"`
	CredentialID string `json:"credential_id,omitempty"`
	LocationID   string `json:"location_id,omitempty"`
	Action       string `json:"action"`
	Status       string `json:"status"`
}
type Event struct {
	ID         string    `json:"id"`
	TargetID   string    `json:"target_id"`
	Action     string    `json:"action"`
	Source     string    `json:"source"`
	Result     string    `json:"result,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
type IssuerObservation struct {
	ID           string     `json:"id"`
	CredentialID string     `json:"credential_id"`
	Issuer       string     `json:"issuer"`
	Source       string     `json:"source"`
	FetchedAt    time.Time  `json:"fetched_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	Status       string     `json:"status"`
	Reason       string     `json:"reason"`
	Activity     string     `json:"activity"`
	Freshness    string     `json:"freshness"`
	Binding      string     `json:"binding"`
	Account      string     `json:"account,omitempty"`
	Project      string     `json:"project,omitempty"`
	KeyID        string     `json:"key_id,omitempty"`
}
type ToolAccess struct {
	ID        string    `json:"id"`
	Provider  string    `json:"provider"`
	StartedAt time.Time `json:"started_at"`
	Cleanup   string    `json:"cleanup"`
}
type Case struct {
	SchemaVersion      int                 `json:"schema_version"`
	ID                 string              `json:"id"`
	Incident           string              `json:"incident"`
	TemplateVersion    string              `json:"template_version"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	Disposition        string              `json:"disposition"`
	Scopes             []Scope             `json:"scopes"`
	Runs               []Run               `json:"runs"`
	Locations          []Location          `json:"locations"`
	Observations       []Observation       `json:"observations"`
	Credentials        []Credential        `json:"credentials"`
	Tasks              []Task              `json:"tasks"`
	Events             []Event             `json:"events"`
	IssuerObservations []IssuerObservation `json:"issuer_observations"`
	ToolAccess         []ToolAccess        `json:"tool_access"`
}

func ID(prefix string) string {
	var b [12]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic("random ID unavailable")
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}
func New(incident string, now time.Time) *Case {
	return &Case{SchemaVersion: SchemaVersion, ID: ID("case"), Incident: incident, TemplateVersion: "1", CreatedAt: now.UTC(), UpdatedAt: now.UTC(), Disposition: "open"}
}
func (c *Case) Credential(id string) *Credential {
	for i := range c.Credentials {
		if c.Credentials[i].ID == id {
			return &c.Credentials[i]
		}
	}
	return nil
}
func (c *Case) AddTask(credential, location, action string) {
	for _, t := range c.Tasks {
		if t.CredentialID == credential && t.LocationID == location && t.Action == action {
			return
		}
	}
	c.Tasks = append(c.Tasks, Task{ID: ID("task"), CredentialID: credential, LocationID: location, Action: action, Status: "pending"})
}
func (c *Case) AddCredential(historical bool, exposure string) string {
	id := ID("cred")
	c.Credentials = append(c.Credentials, Credential{ID: id, Issuer: "unknown", Kind: "unknown", Binding: "unknown", Historical: historical, Exposure: exposure})
	for _, a := range []string{"identify_issuer", "create_replacement", "review_old_key_activity", "revoke_old_credential", "confirm_invalidation", "review_derived_access"} {
		c.AddTask(id, "", a)
	}
	if historical {
		c.AddTask(id, "", "identify_historical_credential")
	}
	return id
}

var Actions = []string{"identify_issuer", "identify_historical_credential", "review_history", "review_classification", "create_replacement", "update_configuration", "replace_or_retire_deployments", "check_health", "review_old_key_activity", "revoke_old_credential", "confirm_invalidation", "review_derived_access", "review_unchecked_scope", "cleanup_tool_access"}
var Statuses = []string{"complete", "partial", "permission_denied", "rate_limited", "unsupported", "not_checked", "failed"}
var Reasons = []string{"ok", "permission_denied", "rate_limited", "request_failed", "invalid_response", "not_found", "cancelled", "limit_reached", "parse_warning", "unreadable", "unknown_type", "references_unresolved", "sealed_inventory_unknown", "deployment_inventory_unchecked", "shared_inventory_unchecked", "organization_secrets_unchecked", "workflow_references_unchecked", "history_unknown", "binding_required", "unsupported_key_class", "account_mismatch", "null_activity", "freshness_unknown", "activity_advanced", "no_change", "operator_reported", "scope_unavailable"}

func In(s string, values ...string) bool { return slices.Contains(values, s) }
func ValidScope(s Scope) bool {
	if !In(s.Source, "local", "vercel", "railway", "github") {
		return false
	}
	for _, v := range []string{s.Project, s.Environment, s.Service, s.Team, s.File} {
		if len(v) > 4096 {
			return false
		}
	}
	return true
}

var validID = regexp.MustCompile(`^(case|cred|task|run|loc|obs|evidence|auth|event)-[a-f0-9]{24}$`)

func (c *Case) Validate() error {
	fail := errors.New("invalid case metadata")
	if c.SchemaVersion != SchemaVersion || !validID.MatchString(c.ID) || c.TemplateVersion != "1" || !In(c.Incident, "vercel-apr-2026", "custom") || !In(c.Disposition, "open", "closed_by_operator") {
		return fail
	}
	if len(c.Observations) > 20000 || len(c.Tasks) > 100000 || len(c.Runs) > 1000 {
		return fail
	}
	ids := map[string]bool{c.ID: true}
	add := func(id string) bool {
		if !validID.MatchString(id) || ids[id] {
			return false
		}
		ids[id] = true
		return true
	}
	locs := map[string]bool{}
	creds := map[string]bool{}
	runs := map[string]bool{}
	for _, s := range c.Scopes {
		if !ValidScope(s) {
			return fail
		}
	}
	for _, l := range c.Locations {
		if !add(l.ID) || !ValidScope(l.Scope) || len(l.Locator) > 8192 || len(l.Variable) > 512 {
			return fail
		}
		locs[l.ID] = true
	}
	for _, r := range c.Runs {
		if !add(r.ID) || r.Requests < 0 || r.FinishedAt.Before(r.StartedAt) || len(r.ToolVersion) > 64 {
			return fail
		}
		runs[r.ID] = true
		for _, v := range r.Coverage {
			if !ValidScope(v.Scope) || !slices.Contains(Statuses, v.Status) || !slices.Contains(Reasons, v.Reason) || v.Count < 0 {
				return fail
			}
		}
	}
	for _, v := range c.Credentials {
		if !add(v.ID) || !In(v.Issuer, "unknown", "aws", "openai", "stripe", "postgres") || !In(v.Kind, "unknown", "iam_access_key", "project_api_key", "password", "api_key") || !In(v.Binding, "unknown", "operator_assertion", "issuer_id") || !In(v.Exposure, "unknown", "potentially_exposed", "confirmed_exposed", "excluded_by_rule") {
			return fail
		}
		for _, x := range []string{v.Account, v.Project, v.KeyID} {
			if len(x) > 256 {
				return fail
			}
		}
		creds[v.ID] = true
	}
	for _, v := range c.Credentials {
		for _, id := range v.ReplacementIDs {
			if !creds[id] || id == v.ID {
				return fail
			}
		}
	}
	for _, o := range c.Observations {
		if !add(o.ID) || !locs[o.LocationID] || !runs[o.RunID] || (o.CredentialID != "" && !creds[o.CredentialID]) || !In(o.Readability, "readable", "write_only", "denied", "unavailable", "unknown_type") || !In(o.Identity, "equal_value", "unknown", "provider_reference", "operator_assertion") || len(o.ProviderType) > 128 || len(o.ProviderUpdatedAt) > 128 {
			return fail
		}
	}
	for _, t := range c.Tasks {
		if !add(t.ID) || !slices.Contains(Actions, t.Action) || !In(t.Status, "pending", "attested", "observed", "blocked", "accepted_exception") || (t.CredentialID != "" && !creds[t.CredentialID]) || (t.LocationID != "" && !locs[t.LocationID]) {
			return fail
		}
	}
	for _, v := range c.ToolAccess {
		if !add(v.ID) || !In(v.Provider, "vercel", "railway", "github", "aws", "openai") || !In(v.Cleanup, "pending", "attested", "retained_by_operator") {
			return fail
		}
	}
	access := map[string]bool{}
	for _, v := range c.ToolAccess {
		access[v.ID] = true
	}
	for _, r := range c.Runs {
		for _, id := range r.AccessIDs {
			if !access[id] {
				return fail
			}
		}
	}
	for _, v := range c.IssuerObservations {
		if !add(v.ID) || !creds[v.CredentialID] || !In(v.Issuer, "aws", "openai", "stripe", "postgres", "unknown") || !In(v.Source, "issuer_api", "operator_attestation") || !slices.Contains(Statuses, v.Status) || !slices.Contains(Reasons, v.Reason) || !In(v.Activity, "usage_observed", "insufficient_evidence", "no_usage_observed_in_window", "unsupported") || v.Freshness != "unknown" || !In(v.Binding, "unknown", "operator_assertion", "issuer_id") {
			return fail
		}
		for _, x := range []string{v.Account, v.Project, v.KeyID} {
			if len(x) > 256 {
				return fail
			}
		}
	}
	for _, v := range c.Events {
		if !add(v.ID) || !ids[v.TargetID] || !In(v.Source, "operator_attestation", "core") || !In(v.Result, "", "pending", "attested", "blocked", "accepted_exception", "retained_by_operator", "closed_by_operator") || !In(v.Action, append(Actions, "bind_issuer", "link_replacement", "close_case", "reopen_case")...) {
			return fail
		}
	}
	return nil
}
