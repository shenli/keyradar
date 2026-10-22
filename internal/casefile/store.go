// Package casefile stores metadata only in a locked, private directory.
package casefile

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/shenli/keyradar/internal/model"
	"github.com/shenli/keyradar/internal/secure"
)

const marker = "KeyRadar metadata case v1\n"

type Store struct{ root *os.Root }

func Open(path string, create bool) (*Store, error) {
	if path == "" {
		return nil, errors.New("case directory required")
	}
	p, e := filepath.Abs(path)
	if e != nil || p == "/" {
		return nil, errors.New("unsafe case path")
	}
	if create {
		if secure.MkdirAll(p) != nil {
			return nil, errors.New("case directory unavailable")
		}
	}
	d, e := secure.OpenFile(p, os.O_RDONLY, 0)
	if e != nil {
		return nil, errors.New("unsafe case directory")
	}
	defer d.Close()
	st, e := d.Stat()
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 || !owned(st) {
		return nil, errors.New("case directory must be owned by you with mode 0700")
	}
	root, e := os.OpenRoot(p)
	if e != nil {
		return nil, errors.New("case directory unavailable")
	}
	other, e := root.Stat(".")
	if e != nil || !os.SameFile(st, other) {
		root.Close()
		return nil, errors.New("case directory changed")
	}
	fail := func(msg string) (*Store, error) { root.Close(); return nil, errors.New(msg) }
	lock, e := root.OpenFile(".lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return fail("case locked; remove a stale .lock only after confirming no writer is running")
	}
	lock.Close()
	cleanup := func(msg string) (*Store, error) { root.Remove(".lock"); return fail(msg) }
	data, e := read(root, ".keyradar", 1024)
	if e != nil {
		if !create {
			return cleanup("case marker missing")
		}
		dir, e := root.Open(".")
		if e != nil {
			return cleanup("case unavailable")
		}
		names, e := dir.Readdirnames(-1)
		dir.Close()
		if e != nil {
			return cleanup("case unavailable")
		}
		for _, n := range names {
			if n != ".lock" {
				return cleanup("refusing nonempty unmarked directory")
			}
		}
		f, e := root.OpenFile(".keyradar", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return cleanup("case marker write failed")
		}
		_, e = f.WriteString(marker)
		f.Close()
		if e != nil {
			return cleanup("case marker write failed")
		}
	} else if string(data) != marker {
		return cleanup("invalid case marker")
	}
	return &Store{root: root}, nil
}
func read(root *os.Root, name string, max int64) ([]byte, error) {
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || !owned(st) || st.Size() > max {
		return nil, errors.New("unsafe case file")
	}
	f, e := root.Open(name)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(st, after) {
		return nil, errors.New("case file changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("case size exceeded")
	}
	return b, nil
}
func (s *Store) Load() (*model.Case, error) {
	b, e := read(s.root, "case.json", 16<<20)
	if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("case read failed")
	}
	var c model.Case
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil {
		return nil, errors.New("invalid case schema")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errors.New("invalid case schema")
	}
	if c.Validate() != nil {
		return nil, errors.New("invalid case metadata")
	}
	return &c, nil
}
func (s *Store) Save(c *model.Case) error {
	if c.Validate() != nil {
		return errors.New("refusing invalid case")
	}
	b, e := json.MarshalIndent(c, "", "  ")
	if e != nil || len(b) > 16<<20 {
		return errors.New("case serialization failed")
	}
	name := model.ID("pending") + ".json"
	f, e := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("case write failed")
	}
	defer s.root.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return errors.New("case write failed")
	}
	if s.root.Rename(name, "case.json") != nil {
		return errors.New("case replacement failed")
	}
	return nil
}
func (s *Store) Clean(forget bool) error {
	c, e := s.Load()
	if e != nil {
		return e
	}
	if !forget {
		for _, a := range c.ToolAccess {
			if a.Cleanup == "pending" {
				return errors.New("tool access cleanup pending; attest cleanup or explicitly use --forget")
			}
		}
	}
	if s.root.Remove("case.json") != nil {
		return errors.New("case deletion failed")
	}
	if s.root.Remove(".keyradar") != nil {
		return errors.New("case marker deletion failed")
	}
	return nil
}
func (s *Store) Close() {
	if s != nil && s.root != nil {
		s.root.Remove(".lock")
		s.root.Close()
		s.root = nil
	}
}
