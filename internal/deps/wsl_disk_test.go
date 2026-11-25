package deps

import (
	"os"
	"path/filepath"
	"testing"
)

// A container is made anew only when WSL keeps its disk in a folder where
// the disk is not; an unknown folder or a disk in place is left alone.
func TestDiskGone(t *testing.T) {
	dir := t.TempDir()
	if diskGone("") {
		t.Error("unknown folder judged")
	}
	if !diskGone(dir) {
		t.Error("missing disk not seen")
	}
	os.WriteFile(filepath.Join(dir, "ext4.vhdx"), []byte("x"), 0o600)
	if diskGone(dir) {
		t.Error("disk in place taken for gone")
	}
}
