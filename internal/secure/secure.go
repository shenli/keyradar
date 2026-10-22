// Package secure supplies bounded IO and redacted authentication handles.
package secure

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
)

type Token struct{ value string }

func NewToken(v string) Token    { return Token{value: v} }
func (t Token) Reveal() string   { return t.value }
func (t Token) String() string   { return "[redacted]" }
func (t Token) GoString() string { return t.String() }
func (t Token) MarshalJSON() ([]byte, error) {
	return nil, errors.New("credential serialization forbidden")
}
func (t Token) MarshalText() ([]byte, error) {
	return nil, errors.New("credential serialization forbidden")
}
func Text(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512]
	}
	return strings.ToValidUTF8(s, "?")
}
func HTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	return &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
}
func Decode(r io.Reader, max int64, v any) error {
	b, e := io.ReadAll(io.LimitReader(r, max+1))
	if e != nil || int64(len(b)) > max {
		return errors.New("bounded read failed")
	}
	if json.Unmarshal(b, v) != nil {
		return errors.New("invalid response")
	}
	return nil
}
func ReadFile(path string, max int64) ([]byte, error) {
	f, e := OpenFile(path, os.O_RDONLY, 0)
	if e != nil {
		return nil, errors.New("file unavailable")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > max {
		return nil, errors.New("file rejected")
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(b)) > max {
		return nil, errors.New("file rejected")
	}
	return b, nil
}
