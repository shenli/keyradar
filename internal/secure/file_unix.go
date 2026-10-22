//go:build darwin || linux

package secure

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenFile traverses every component using directory descriptors and O_NOFOLLOW.
func OpenFile(path string, flags int, mode os.FileMode) (*os.File, error) {
	p, e := filepath.Abs(path)
	if e != nil {
		return nil, errors.New("invalid path")
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/")
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if err != nil {
			return nil, errors.New("unsafe path")
		}
		fd = next
	}
	out, e := unix.Openat(fd, parts[len(parts)-1], flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(mode.Perm()))
	unix.Close(fd)
	if e != nil {
		return nil, errors.New("file open failed")
	}
	return os.NewFile(uintptr(out), p), nil
}

// MkdirAll creates private directories without following symlinks in any component.
func MkdirAll(path string) error {
	p, err := filepath.Abs(path)
	if err != nil || p == "/" {
		return errors.New("unsafe directory path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("directory unavailable")
	}
	defer func() { unix.Close(fd) }()
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(p), "/"), "/") {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr == unix.ENOENT {
			if mkdirErr := unix.Mkdirat(fd, part, 0700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				return errors.New("directory creation failed")
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if openErr != nil {
			return errors.New("unsafe directory path")
		}
		unix.Close(fd)
		fd = next
	}
	return nil
}
