//go:build windows

package winutil

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32                  = windows.NewLazySystemDLL("user32.dll")
	procEnumWindows         = user32.NewProc("EnumWindows")
	procGetWindowTextW      = user32.NewProc("GetWindowTextW")
	procGetClassNameW       = user32.NewProc("GetClassNameW")
	procIsWindowVisible     = user32.NewProc("IsWindowVisible")
	procIsIconic            = user32.NewProc("IsIconic")
	procShowWindow          = user32.NewProc("ShowWindow")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procBringWindowToTop    = user32.NewProc("BringWindowToTop")
	procKeybdEvent          = user32.NewProc("keybd_event")
)

// AppWindowTitle is the <title> of the UI page (internal/web/index.html).
const AppWindowTitle = "VPNer"

const (
	swRestore      = 9
	swShow         = 5
	vkMenu         = 0x12
	keyeventfKeyUp = 0x0002
)

func windowText(h uintptr, proc *windows.LazyProc) string {
	buf := make([]uint16, 256)
	n, _, _ := proc.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf[:n])
}

// findAppWindows returns visible browser (Chromium/Edge) top-level windows
// whose title is exactly title — the VPNer app windows.
func findAppWindows(title string) []uintptr {
	var found []uintptr
	cb := syscall.NewCallback(func(h, _ uintptr) uintptr {
		if v, _, _ := procIsWindowVisible.Call(h); v == 0 {
			return 1
		}
		if windowText(h, procGetClassNameW) == "Chrome_WidgetWin_1" && windowText(h, procGetWindowTextW) == title {
			found = append(found, h)
		}
		return 1
	})
	procEnumWindows.Call(cb, 0)
	return found
}

// FocusAppWindow brings an already open VPNer window to the front.
// It reports false when no such window exists.
func FocusAppWindow(title string) bool {
	wins := findAppWindows(title)
	if len(wins) == 0 {
		return false
	}
	h := wins[0]
	if iconic, _, _ := procIsIconic.Call(h); iconic != 0 {
		procShowWindow.Call(h, swRestore)
	} else {
		procShowWindow.Call(h, swShow)
	}
	// Windows only lets the foreground process change the foreground
	// window; a synthetic Alt press lifts that restriction for us.
	procKeybdEvent.Call(vkMenu, 0, 0, 0)
	procKeybdEvent.Call(vkMenu, 0, keyeventfKeyUp, 0)
	procBringWindowToTop.Call(h)
	procSetForegroundWindow.Call(h)
	return true
}

// CountAppWindows is used to verify that no duplicate windows are opened.
func CountAppWindows(title string) int { return len(findAppWindows(title)) }
