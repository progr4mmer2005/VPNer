//go:build windows

package hyperv

import (
	"vpner/internal/i18n"

	"archive/tar"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/ulikunitz/xz"
	"golang.org/x/sys/windows"

	"vpner/internal/deps"
)

// EnsureBaseImage downloads the Debian cloud image (once) and turns its raw
// disk into a fixed VHD that Hyper-V can use as the source for VM disks.
func EnsureBaseImage(cacheDir, imagesDir string, progress deps.Progress) (string, error) {
	a, err := deps.DebianCloud()
	if err != nil {
		return "", err
	}
	out := filepath.Join(imagesDir, "debian-13-"+deps.DebianRelease+".vhd")
	if st, err := os.Stat(out); err == nil && st.Size() > 1<<30 {
		// VPNer 0.3.0 and earlier wrote the image as an NTFS sparse file,
		// which newer Hyper-V refuses as the source of Convert-VHD. Make it a
		// plain file; if that fails, unpack it again from the archive.
		if progress != nil {
			progress(i18n.T("hyperv.preparingVirtualMachineDisk"), 0, -1)
		}
		if err := plainFile(out); err == nil {
			return out, nil
		}
		os.Remove(out)
	}
	archive, err := deps.Fetch(a, cacheDir, progress)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(imagesDir, 0o755); err != nil {
		return "", err
	}
	tmp := out + ".part"
	if err := extractRawToVHD(archive, tmp, progress); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return out, os.Rename(tmp, out)
}

func extractRawToVHD(archive, dst string, progress deps.Progress) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	xr, err := xz.NewReader(f)
	if err != nil {
		return fmt.Errorf(i18n.T("hyperv.vmImage"), err)
	}
	tr := tar.NewReader(xr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New(i18n.T("hyperv.vmImageArchiveHasNo"))
		}
		if err != nil {
			return fmt.Errorf(i18n.T("hyperv.vmImage"), err)
		}
		if strings.HasSuffix(h.Name, ".raw") {
			if err := writeVHD(tr, h.Size, dst, progress); err != nil {
				return err
			}
			// a compressed folder would compress the new file as well
			return plainFile(dst)
		}
	}
}

// writeVHD writes the raw disk and appends a fixed-VHD footer. The zero
// blocks are written out too: Hyper-V refuses a sparse, compressed or
// encrypted file as the source of Convert-VHD (0xC03A001A).
func writeVHD(r io.Reader, size int64, dst string, progress deps.Progress) error {
	if size%512 != 0 {
		return errors.New(i18n.T("hyperv.vmImageDiskSizeIs"))
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	buf := make([]byte, 1<<20)
	var done int64
	last := time.Time{}
	for done < size {
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), size-done)])
		if n > 0 {
			if _, err := out.Write(buf[:n]); err != nil {
				return err
			}
			done += int64(n)
		}
		if err != nil && done < size {
			return fmt.Errorf(i18n.T("hyperv.vmImage"), err)
		}
		if progress != nil && time.Since(last) > 300*time.Millisecond {
			progress(i18n.T("hyperv.preparingVirtualMachineDisk"), done, size)
			last = time.Now()
		}
	}
	if _, err := out.Write(vhdFooter(uint64(size))); err != nil {
		return err
	}
	return out.Sync()
}

const (
	fsctlSetSparse      = 0x000900c4
	fsctlSetCompression = 0x0009c040
)

// plainFile clears the NTFS sparse and compressed flags of a file. Clearing
// the sparse flag makes NTFS allocate the ranges that were left out, so the
// file then holds every byte; its content and length stay the same.
func plainFile(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&(windows.FILE_ATTRIBUTE_SPARSE_FILE|windows.FILE_ATTRIBUTE_COMPRESSED) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	h := windows.Handle(f.Fd())
	var ret uint32
	if attrs&windows.FILE_ATTRIBUTE_COMPRESSED != 0 {
		none := uint16(0) // COMPRESSION_FORMAT_NONE
		if err := windows.DeviceIoControl(h, fsctlSetCompression, (*byte)(unsafe.Pointer(&none)), 2, nil, 0, &ret, nil); err != nil {
			return err
		}
	}
	if attrs&windows.FILE_ATTRIBUTE_SPARSE_FILE != 0 {
		off := byte(0) // FILE_SET_SPARSE_BUFFER{SetSparse: FALSE}
		if err := windows.DeviceIoControl(h, fsctlSetSparse, &off, 1, nil, 0, &ret, nil); err != nil {
			return err
		}
	}
	return nil
}

// vhdFooter builds the 512-byte footer of a fixed VHD (VHD spec v1.0).
func vhdFooter(size uint64) []byte {
	f := make([]byte, 512)
	copy(f[0:], "conectix")
	binary.BigEndian.PutUint32(f[8:], 2)                   // features: reserved bit
	binary.BigEndian.PutUint32(f[12:], 0x00010000)         // format version
	binary.BigEndian.PutUint64(f[16:], 0xFFFFFFFFFFFFFFFF) // data offset: none (fixed)
	ts := time.Since(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)).Seconds()
	binary.BigEndian.PutUint32(f[24:], uint32(ts))
	copy(f[28:], "vpnr")
	binary.BigEndian.PutUint32(f[32:], 0x00010000)
	copy(f[36:], "Wi2k")
	binary.BigEndian.PutUint64(f[40:], size)
	binary.BigEndian.PutUint64(f[48:], size)
	c, h, s := chs(size / 512)
	binary.BigEndian.PutUint16(f[56:], c)
	f[58], f[59] = h, s
	binary.BigEndian.PutUint32(f[60:], 2) // disk type: fixed
	rand.Read(f[68:84])                   // unique id
	var sum uint32
	for _, b := range f {
		sum += uint32(b)
	}
	binary.BigEndian.PutUint32(f[64:], ^sum)
	return f
}

// chs implements the geometry algorithm from the VHD specification.
func chs(sectors uint64) (uint16, uint8, uint8) {
	if sectors > 65535*16*255 {
		sectors = 65535 * 16 * 255
	}
	var spt, heads, cth uint64
	if sectors >= 65535*16*63 {
		spt, heads = 255, 16
		cth = sectors / spt
	} else {
		spt = 17
		cth = sectors / spt
		heads = (cth + 1023) / 1024
		if heads < 4 {
			heads = 4
		}
		if cth >= heads*1024 || heads > 16 {
			spt, heads = 31, 16
			cth = sectors / spt
		}
		if cth >= heads*1024 {
			spt, heads = 63, 16
			cth = sectors / spt
		}
	}
	return uint16(cth / heads), uint8(heads), uint8(spt)
}
