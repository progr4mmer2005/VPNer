//go:build !windows

package app

import (
	"os"
	"time"
)

// fileCreated returns when a file was created; without that information on
// this system, when it was last written (zero when unknown).
func fileCreated(path string) time.Time {
	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}
