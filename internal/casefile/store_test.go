package casefile

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/shenli/keyradar/internal/scan"
)

func directory(t *testing.T) string {
	t.Helper()
	p, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(p, 0700)
	return p
}
func TestRoundtripLockAndClean(t *testing.T) {
	p := directory(t)
	s, e := Open(p, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if _, e = Open(p, false); e == nil {
		t.Fatal("concurrent writer accepted")
	}
	c := scan.Demo()
	if e = s.Save(c); e != nil {
		t.Fatal(e)
	}
	got, e := s.Load()
	if e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(c)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatal("case changed on roundtrip")
	}
	st, _ := os.Stat(filepath.Join(p, "case.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("case permissions")
	}
	if s.Clean(false) == nil {
		t.Fatal("cleanup silently forgot pending tokens")
	}
	if e = s.Clean(true); e != nil {
		t.Fatal(e)
	}
}
func TestInvalidSavePreservesCase(t *testing.T) {
	p := directory(t)
	s, e := Open(p, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c := scan.Demo()
	if s.Save(c) != nil {
		t.Fatal("save")
	}
	id := c.ID
	c.SchemaVersion = 99
	if s.Save(c) == nil {
		t.Fatal("invalid save accepted")
	}
	got, e := s.Load()
	if e != nil || got.ID != id || got.SchemaVersion != 1 {
		t.Fatal("prior case lost")
	}
}
func TestRejectUnsafeLocations(t *testing.T) {
	p := directory(t)
	os.WriteFile(filepath.Join(p, "unrelated"), []byte("leave me"), 0600)
	if _, e := Open(p, true); e == nil {
		t.Fatal("unmarked nonempty accepted")
	}
	base := directory(t)
	target := directory(t)
	os.Symlink(target, filepath.Join(base, "link"))
	if _, e := Open(filepath.Join(base, "link"), true); e == nil {
		t.Fatal("symlink directory accepted")
	}
	os.Chmod(target, 0755)
	if _, e := Open(target, true); e == nil {
		t.Fatal("public directory accepted")
	}
}
func TestRejectCorruptAndSymlinkState(t *testing.T) {
	p := directory(t)
	s, e := Open(p, true)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	os.WriteFile(filepath.Join(p, "case.json"), []byte(`{"schema_version":999,"raw":"PRIVATE_CANARY"}`), 0600)
	if _, e = s.Load(); e == nil {
		t.Fatal("corrupt case accepted")
	}
	os.Remove(filepath.Join(p, "case.json"))
	other := filepath.Join(directory(t), "private")
	os.WriteFile(other, []byte("PRIVATE_CANARY"), 0600)
	os.Symlink(other, filepath.Join(p, "case.json"))
	if _, e = s.Load(); e == nil {
		t.Fatal("external symlink read")
	}
}

func TestCreationDoesNotFollowSymlinkParent(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	outside := filepath.Join(root, "outside")
	if err := os.Mkdir(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	if s, err := Open(filepath.Join(root, "alias", "new-case"), true); err == nil {
		s.Close()
		t.Fatal("symlink parent accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "new-case")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created directories through symlink")
	}
}
