//go:build windows

package winutil

import (
	"vpner/internal/i18n"

	"errors"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	comdlg32                 = windows.NewLazySystemDLL("comdlg32.dll")
	procGetSaveFileNameW     = comdlg32.NewProc("GetSaveFileNameW")
	procCommDlgExtendedError = comdlg32.NewProc("CommDlgExtendedError")
	procOpenClipboard        = user32.NewProc("OpenClipboard")
	procCloseClipboard       = user32.NewProc("CloseClipboard")
	procGetClipboardData     = user32.NewProc("GetClipboardData")
	procGlobalLock           = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalLock")
	procGlobalUnlock         = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalUnlock")
)

// openFileName is OPENFILENAMEW.
type openFileName struct {
	StructSize      uint32
	Owner           uintptr
	Instance        uintptr
	Filter          *uint16
	CustomFilter    *uint16
	MaxCustomFilter uint32
	FilterIndex     uint32
	File            *uint16
	MaxFile         uint32
	FileTitle       *uint16
	MaxFileTitle    uint32
	InitialDir      *uint16
	Title           *uint16
	Flags           uint32
	FileOffset      uint16
	FileExtension   uint16
	DefExt          *uint16
	CustData        uintptr
	FnHook          uintptr
	TemplateName    *uint16
	Reserved        uintptr
	Reserved2       uint32
	FlagsEx         uint32
}

const (
	ofnOverwritePrompt = 0x2
	ofnHideReadOnly    = 0x4
	ofnNoChangeDir     = 0x8
	ofnPathMustExist   = 0x800
	ofnExplorer        = 0x80000
)

// SaveFileDialog shows the standard Windows "Save as" dialog over the VPNer
// window. ok is false when the user cancels.
func SaveFileDialog(title, fileName, filterName, ext string) (path string, ok bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// "Name (*.ext)\0*.ext\0\0"
	filter := windows.StringToUTF16(filterName + " (*." + ext + ")")
	filter = append(filter, windows.StringToUTF16("*."+ext)...)
	filter = append(filter, 0)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	copy(buf, windows.StringToUTF16(fileName))
	t, _ := windows.UTF16PtrFromString(title)
	def, _ := windows.UTF16PtrFromString(ext)
	dir, _ := windows.UTF16PtrFromString(filepath.Join(userHome(), "Desktop"))
	ofn := openFileName{
		Filter: &filter[0], FilterIndex: 1, File: &buf[0], MaxFile: uint32(len(buf)),
		Title: t, DefExt: def, InitialDir: dir,
		Flags: ofnOverwritePrompt | ofnHideReadOnly | ofnNoChangeDir | ofnPathMustExist | ofnExplorer,
	}
	ofn.StructSize = uint32(unsafe.Sizeof(ofn))
	if wins := findAppWindows(AppWindowTitle); len(wins) > 0 {
		ofn.Owner = wins[0] // modal over the VPNer window
	}
	if r, _, _ := procGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn))); r == 0 {
		if code, _, _ := procCommDlgExtendedError.Call(); code != 0 {
			return "", false, errors.New(i18n.T("winutil.couldNotOpenSaveDialog"))
		}
		return "", false, nil // cancelled
	}
	return windows.UTF16ToString(buf), true, nil
}

func userHome() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_Profile, 0); err == nil {
		return p
	}
	return ""
}

// ClipboardText returns the text on the Windows clipboard.
func ClipboardText() (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	opened := false
	for i := 0; i < 10 && !opened; i++ {
		if r, _, _ := procOpenClipboard.Call(0); r != 0 {
			opened = true
		} else {
			time.Sleep(20 * time.Millisecond) // another program holds it
		}
	}
	if !opened {
		return "", errors.New(i18n.T("winutil.clipboardIsBusyWithAnother"))
	}
	defer procCloseClipboard.Call()
	const cfUnicodeText = 13
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		return "", nil
	}
	defer procGlobalUnlock.Call(h)
	return windows.UTF16PtrToString(*(**uint16)(unsafe.Pointer(&p))), nil
}
