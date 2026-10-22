//go:build !linux && !darwin

package casefile

import "os"

func owned(os.FileInfo) bool { return false }
