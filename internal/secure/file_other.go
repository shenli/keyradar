//go:build !darwin && !linux

package secure

import (
	"errors"
	"os"
)

func OpenFile(string, int, os.FileMode) (*os.File, error) {
	return nil, errors.New("safe file access supported only on macOS/Linux")
}

func MkdirAll(string) error { return errors.New("safe file access supported only on macOS/Linux") }
