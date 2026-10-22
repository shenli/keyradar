package report

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/shenli/keyradar/internal/model"
)

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriteFailuresPropagate(t *testing.T) {
	for _, format := range []string{"json", "markdown"} {
		if !errors.Is(Write(brokenWriter{}, model.New("custom", time.Now()), format, true), io.ErrClosedPipe) {
			t.Fatal("output error swallowed")
		}
	}
}

func TestMissingCurrentObservationIsUnknown(t *testing.T) {
	c := model.New("custom", time.Now())
	id := c.AddCredential(false, "unknown")
	loc := model.ID("loc")
	oldRun, newRun := model.ID("run"), model.ID("run")
	c.Locations = []model.Location{{ID: loc, Scope: model.Scope{Source: "local", File: "private-path"}, Variable: "private-name"}}
	c.Runs = []model.Run{{ID: oldRun}, {ID: newRun}}
	c.Observations = []model.Observation{{ID: model.ID("obs"), RunID: oldRun, LocationID: loc, CredentialID: id, Readability: "readable", Identity: "equal_value"}}
	r, err := Build(c, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Credentials[0].Locations) != 0 || r.Locations[0].Readability != "unavailable" || r.Locations[0].Identity != "unknown" {
		t.Fatal("historical observation treated as current")
	}
	var b strings.Builder
	if Write(&b, c, "json", true) != nil || strings.Contains(b.String(), "private-") {
		t.Fatal("private labels escaped")
	}
}
