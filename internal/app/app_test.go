package app

import (
	"testing"
	"time"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/scan"
)

func TestAttestationAndClosure(t *testing.T) {
	c := scan.Demo()
	now := time.Now()
	if Record(c, c.Tasks[0].ID, "observed", now) == nil {
		t.Fatal("human created machine observation")
	}
	if Close(c, now) == nil {
		t.Fatal("closed with pending tasks")
	}
	for _, v := range c.Tasks {
		if e := Record(c, v.ID, "accepted_exception", now); e != nil {
			t.Fatal(e)
		}
	}
	if e := Close(c, now); e != nil {
		t.Fatal(e)
	}
	if c.Disposition != "closed_by_operator" {
		t.Fatal("closure missing")
	}
	if c.Validate() != nil {
		t.Fatal("invalid case")
	}
}
func TestReplacementCycle(t *testing.T) {
	c := model.New("custom", time.Now())
	a := c.AddCredential(false, "unknown")
	b := c.AddCredential(false, "unknown")
	if Link(c, a, b, time.Now()) != nil {
		t.Fatal("link failed")
	}
	if Link(c, b, a, time.Now()) == nil {
		t.Fatal("cycle accepted")
	}
}

func TestSecretValueCannotBeBoundAsKeyID(t *testing.T) {
	c := model.New("custom", time.Now())
	id := c.AddCredential(true, "unknown")
	if Bind(c, id, "openai", "org_example", "proj_example", "sk-proj-synthetic-never-valid", "project_api_key", time.Now()) == nil {
		t.Fatal("secret value accepted as issuer ID")
	}
}
