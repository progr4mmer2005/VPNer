//go:build windows

package hyperv

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func attrsOf(t *testing.T, path string) uint32 {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := windows.GetFileAttributes(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A disk with zero blocks: the old code skipped them and made a sparse file.
func testDisk() []byte {
	d := make([]byte, 3<<20)
	copy(d[512:], "boot")
	copy(d[2<<20+7:], "data")
	return d
}

// Hyper-V refuses a sparse file as the source of Convert-VHD (0xC03A001A),
// so the image must be a plain file holding every byte.
func TestWriteVHDIsPlain(t *testing.T) {
	disk := testDisk()
	dst := filepath.Join(t.TempDir(), "base.vhd")
	if err := writeVHD(bytes.NewReader(disk), int64(len(disk)), dst, nil); err != nil {
		t.Fatal(err)
	}
	if a := attrsOf(t, dst); a&(windows.FILE_ATTRIBUTE_SPARSE_FILE|windows.FILE_ATTRIBUTE_COMPRESSED) != 0 {
		t.Fatalf("the image must be a plain file, attributes %#x", a)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(disk)+512 || !bytes.Equal(got[:len(disk)], disk) {
		t.Fatalf("disk content changed: %d bytes", len(got))
	}
	if string(got[len(disk):len(disk)+8]) != "conectix" {
		t.Error("no VHD footer")
	}
}

// An image written by VPNer 0.3.0 and earlier is sparse; plainFile turns it
// into a plain file with the same content.
func TestPlainFileClearsSparse(t *testing.T) {
	disk := testDisk()
	dst := filepath.Join(t.TempDir(), "old.vhd")
	f, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	var ret uint32
	if err := windows.DeviceIoControl(windows.Handle(f.Fd()), fsctlSetSparse, nil, 0, nil, 0, &ret, nil); err != nil {
		f.Close()
		t.Skipf("the temp folder's file system has no sparse files: %v", err)
	}
	if _, err := f.Write(disk[:1<<20]); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(2<<20, 0); err != nil { // the second MiB is all zeros: left out
		t.Fatal(err)
	}
	if _, err := f.Write(disk[2<<20:]); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if attrsOf(t, dst)&windows.FILE_ATTRIBUTE_SPARSE_FILE == 0 {
		t.Fatal("the test file should be sparse")
	}

	if err := plainFile(dst); err != nil {
		t.Fatal(err)
	}
	if attrsOf(t, dst)&windows.FILE_ATTRIBUTE_SPARSE_FILE != 0 {
		t.Fatal("the sparse flag is still set")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, disk) {
		t.Fatal("content changed")
	}
	// a plain file stays as it is
	if err := plainFile(dst); err != nil {
		t.Fatal(err)
	}
}
