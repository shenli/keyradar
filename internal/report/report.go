// Package report consumes metadata-only DTOs, never provider response objects.
package report

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
)

type Credential struct {
	ID           string   `json:"id"`
	Issuer       string   `json:"issuer"`
	Historical   bool     `json:"historical"`
	Exposure     string   `json:"exposure"`
	Binding      string   `json:"binding"`
	Locations    []string `json:"locations"`
	Replacements []string `json:"replacements,omitempty"`
}
type Location struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Label       string `json:"label"`
	Readability string `json:"readability"`
	Identity    string `json:"identity"`
}
type Coverage struct {
	Source string `json:"source"`
	Scope  string `json:"scope"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}
type Evidence struct {
	CredentialID string     `json:"credential_id"`
	Issuer       string     `json:"issuer"`
	Source       string     `json:"source"`
	FetchedAt    time.Time  `json:"fetched_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	Activity     string     `json:"activity"`
	Status       string     `json:"status"`
	Reason       string     `json:"reason"`
	Freshness    string     `json:"freshness"`
	Binding      string     `json:"binding"`
}
type Audit struct {
	RunID      string    `json:"run_id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Requests   int       `json:"requests"`
	AccessIDs  []string  `json:"access_ids"`
}
type Report struct {
	Audit             []Audit            `json:"audit,omitempty"`
	Access            []model.ToolAccess `json:"tool_access,omitempty"`
	SchemaVersion     int                `json:"schema_version"`
	Shareable         bool               `json:"shareable"`
	GeneratedAt       time.Time          `json:"generated_at"`
	Incident          string             `json:"incident"`
	Disposition       string             `json:"disposition"`
	CoverageStatus    string             `json:"coverage_status"`
	Credentials       []Credential       `json:"credentials"`
	Locations         []Location         `json:"locations"`
	Coverage          []Coverage         `json:"coverage"`
	Tasks             []model.Task       `json:"tasks"`
	IssuerEvidence    []Evidence         `json:"issuer_evidence"`
	ToolAccessPending int                `json:"tool_access_pending"`
	Limitations       []string           `json:"limitations"`
}

func Build(c *model.Case, share bool) (Report, error) {
	if c.Validate() != nil {
		return Report{}, errors.New("invalid case for report")
	}
	r := Report{SchemaVersion: 1, Shareable: share, GeneratedAt: c.UpdatedAt, Incident: c.Incident, Disposition: c.Disposition, CoverageStatus: "complete", Credentials: []Credential{}, Locations: []Location{}, Coverage: []Coverage{}, Tasks: []model.Task{}, IssuerEvidence: []Evidence{}, Limitations: []string{"Collection is scoped; not observed does not mean absent.", "Issuer silence does not prove no consumers remain; freshness is unknown.", "Configuration updates do not establish deployment rollout or issuer revocation.", "Whole-value matching cannot find all embedded or encoded credential copies.", "Cross-run value replacement is not proven without independent evidence.", "Local metadata is not encrypted; operator reports are private."}}
	alias := map[string]string{"": ""}
	for i, v := range c.Credentials {
		alias[v.ID] = fmt.Sprintf("C%d", i+1)
	}
	for i, v := range c.Locations {
		alias[v.ID] = fmt.Sprintf("L%d", i+1)
	}
	for i, v := range c.Tasks {
		alias[v.ID] = fmt.Sprintf("T%d", i+1)
	}
	ref := func(id string) string {
		if share {
			return alias[id]
		}
		return id
	}
	latest := map[string]model.Observation{}
	for _, o := range c.Observations {
		if len(c.Runs) > 0 && o.RunID == c.Runs[len(c.Runs)-1].ID {
			latest[o.LocationID] = o
		}
	}
	for _, l := range c.Locations {
		o := latest[l.ID]
		if o.ID == "" {
			o.Readability = "unavailable"
			o.Identity = "unknown"
		}
		label := secure.Text(l.Scope.Project + "/" + l.Scope.Environment + "/" + l.Scope.Service + "/" + l.Variable)
		if l.Scope.Source == "local" {
			label = secure.Text(l.Scope.File + ":" + l.Variable)
		}
		if share {
			label = alias[l.ID]
		}
		r.Locations = append(r.Locations, Location{ID: ref(l.ID), Source: l.Scope.Source, Label: label, Readability: o.Readability, Identity: o.Identity})
	}
	for _, cr := range c.Credentials {
		v := Credential{ID: ref(cr.ID), Issuer: cr.Issuer, Historical: cr.Historical, Exposure: cr.Exposure, Binding: cr.Binding, Locations: []string{}}
		for _, l := range c.Locations {
			if latest[l.ID].CredentialID == cr.ID {
				v.Locations = append(v.Locations, ref(l.ID))
			}
		}
		for _, id := range cr.ReplacementIDs {
			v.Replacements = append(v.Replacements, ref(id))
		}
		r.Credentials = append(r.Credentials, v)
	}
	if len(c.Runs) == 0 {
		r.CoverageStatus = "not_checked"
	} else {
		last := c.Runs[len(c.Runs)-1]
		for i, v := range last.Coverage {
			label := secure.Text(v.Scope.Project + "/" + v.Scope.Environment)
			if v.Scope.Source == "local" {
				label = secure.Text(v.Scope.File)
			}
			if share {
				label = fmt.Sprintf("scope-%d", i+1)
			}
			r.Coverage = append(r.Coverage, Coverage{Source: v.Scope.Source, Scope: label, Status: v.Status, Reason: v.Reason, Count: v.Count})
			if v.Status != "complete" {
				r.CoverageStatus = "partial"
			}
		}
	}
	for _, t := range c.Tasks {
		t.ID = ref(t.ID)
		t.CredentialID = ref(t.CredentialID)
		t.LocationID = ref(t.LocationID)
		r.Tasks = append(r.Tasks, t)
	}
	for _, v := range c.IssuerObservations {
		r.IssuerEvidence = append(r.IssuerEvidence, Evidence{CredentialID: ref(v.CredentialID), Issuer: v.Issuer, Source: v.Source, FetchedAt: v.FetchedAt, LastUsedAt: v.LastUsedAt, Activity: v.Activity, Status: v.Status, Reason: v.Reason, Freshness: v.Freshness, Binding: v.Binding})
	}
	for _, a := range c.ToolAccess {
		if a.Cleanup == "pending" {
			r.ToolAccessPending++
		}
	}
	if !share {
		for _, run := range c.Runs {
			r.Audit = append(r.Audit, Audit{RunID: run.ID, StartedAt: run.StartedAt, FinishedAt: run.FinishedAt, Requests: run.Requests, AccessIDs: run.AccessIDs})
		}
		r.Access = append([]model.ToolAccess(nil), c.ToolAccess...)
	}
	return r, nil
}
func markdown(s string) string {
	s = secure.Text(s)
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "`", "&#96;", "[", "&#91;", "]", "&#93;", "\\", "&#92;", "*", "&#42;", "_", "&#95;").Replace(s)
}
func Write(w io.Writer, c *model.Case, format string, share bool) error {
	r, e := Build(c, share)
	if e != nil {
		return e
	}
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "markdown":
		destination := w
		var buffer strings.Builder
		w = &buffer
		fmt.Fprintf(w, "# KeyRadar incident report\n\nIncident: %s · Coverage: **%s** · Disposition: %s\n\n", r.Incident, r.CoverageStatus, r.Disposition)
		if r.Shareable {
			fmt.Fprintln(w, "Shareable metadata projection. External names and identifiers are omitted.")
		} else {
			fmt.Fprintln(w, "Private operator report. Use --shareable before sharing with an agent or public issue.")
		}
		fmt.Fprintln(w, "\n## Credentials\n\n| Credential | Issuer | Historical | Exposure | Current locations |\n|---|---|---|---|---|")
		for _, v := range r.Credentials {
			fmt.Fprintf(w, "| %s | %s | %t | %s | %s |\n", v.ID, v.Issuer, v.Historical, v.Exposure, strings.Join(v.Locations, ", "))
		}
		fmt.Fprintln(w, "\n## Locations\n\n| Location | Source | Label | Readability | Identity |\n|---|---|---|---|---|")
		for _, v := range r.Locations {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", v.ID, v.Source, markdown(v.Label), v.Readability, v.Identity)
		}
		fmt.Fprintln(w, "\n## Coverage\n\n| Source | Scope | Status | Reason | Count |\n|---|---|---|---|---|")
		for _, v := range r.Coverage {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n", v.Source, markdown(v.Scope), v.Status, v.Reason, v.Count)
		}
		fmt.Fprint(w, "\n## Tasks\n\n")
		for _, t := range r.Tasks {
			fmt.Fprintf(w, "- %s: %s [%s] credential=%s location=%s\n", t.ID, t.Action, t.Status, t.CredentialID, t.LocationID)
		}
		fmt.Fprint(w, "\n## Issuer evidence\n\n")
		for _, v := range r.IssuerEvidence {
			last := "unknown"
			if v.LastUsedAt != nil {
				last = v.LastUsedAt.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(w, "- %s / %s: %s; last used %s; source %s; result %s (%s); freshness %s; binding %s.\n", v.CredentialID, v.Issuer, v.Activity, last, v.Source, v.Status, v.Reason, v.Freshness, v.Binding)
		}
		if !share {
			fmt.Fprint(w, "\n## Scan audit\n\n")
			for _, a := range r.Audit {
				fmt.Fprintf(w, "- %s: %s to %s; requests=%d; auth sessions=%s\n", a.RunID, a.StartedAt.Format(time.RFC3339), a.FinishedAt.Format(time.RFC3339), a.Requests, strings.Join(a.AccessIDs, ", "))
			}
			for _, a := range r.Access {
				fmt.Fprintf(w, "- %s: %s; cleanup=%s\n", a.ID, a.Provider, a.Cleanup)
			}
		}
		fmt.Fprintf(w, "\nTool-access cleanup pending: **%d**. Local deletion does not revoke credentials.\n\n", r.ToolAccessPending)
		for _, v := range r.Limitations {
			fmt.Fprintf(w, "- %s\n", v)
		}
		_, err := io.WriteString(destination, buffer.String())
		return err
	default:
		return errors.New("format must be markdown or json")
	}
}
