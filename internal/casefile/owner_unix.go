//go:build linux || darwin

package casefile

import (
	"os"
	"syscall"
)

func owned(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && int(s.Uid) == os.Getuid()
}
