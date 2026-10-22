package templates

import "testing"

func TestConservativeIncidentRules(t *testing.T) {
	v, err := Load("vercel-apr-2026")
	if err != nil || v.WindowStart != nil || v.WindowEnd != nil {
		t.Fatal("unsubstantiated attack window")
	}
	for _, tc := range []struct{ source, readability, want string }{
		{"vercel", "readable", "potentially_exposed"}, {"vercel", "write_only", "unknown"}, {"railway", "readable", "unknown"},
	} {
		if got := Exposure(v.ID, tc.source, tc.readability); got != tc.want {
			t.Fatalf("exposure %s", got)
		}
	}
	if _, err := Load("../custom"); err == nil {
		t.Fatal("unexpected template accepted")
	}
}
