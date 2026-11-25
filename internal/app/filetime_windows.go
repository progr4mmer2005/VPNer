//go:build windows

package app

import (
	"os"
	"syscall"
	"time"
)

// fileCreated returns when a file was created (zero when unknown).
func fileCreated(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
		return time.Unix(0, d.CreationTime.Nanoseconds())
	}
	return st.ModTime()
}
