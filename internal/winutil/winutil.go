//go:build windows

// Package winutil wraps the Windows specifics: elevation, single instance,
// process listing and opening the UI window.
package winutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func IsAdmin() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// RelaunchElevated restarts the current executable through UAC.
func RelaunchElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	cwd, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = syscall.EscapeArg(a)
	}
	params, _ := windows.UTF16PtrFromString(strings.Join(q, " "))
	return windows.ShellExecute(0, verb, file, params, cwd, windows.SW_NORMAL)
}

// SingleInstance returns false if another instance holds the mutex.
func SingleInstance(name string) (bool, func()) {
	n, _ := windows.UTF16PtrFromString("Local\\" + name)
	h, err := windows.CreateMutex(nil, false, n)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(h)
		return false, func() {}
	}
	if err != nil {
		return true, func() {}
	}
	return true, func() { windows.CloseHandle(h) }
}

type Process struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
}

// Processes lists running executables (unique by name), for the rule editor.
func Processes() []Process {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	seen := map[string]bool{}
	var out []Process
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		name := windows.UTF16ToString(e.ExeFile[:])
		key := strings.ToLower(name)
		if seen[key] || e.ProcessID <= 4 {
			continue
		}
		seen[key] = true
		out = append(out, Process{Name: name, Path: processPath(e.ProcessID)})
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

func processPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// OpenURL opens a URL in the default browser.
func OpenURL(url string) error {
	return hidden(exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)).Start()
}

func edgePath() string {
	for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "LocalAppData"} {
		p := filepath.Join(os.Getenv(env), "Microsoft", "Edge", "Application", "msedge.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// OpenAppWindow shows the UI as a standalone app window (Edge app mode, which
// ships with every Windows 10/11), falling back to the default browser.
func OpenAppWindow(url, profileDir string) error {
	// One window only: if it is already open, just bring it to the front.
	if FocusAppWindow(AppWindowTitle) {
		return nil
	}
	if _, err := StartAppWindow(url, profileDir, 1180, 820); err == nil {
		return nil
	}
	return OpenURL(url)
}

// StartAppWindow opens url as an app window of Microsoft Edge with its own
// profile and returns the browser process.
func StartAppWindow(url, profileDir string, width, height int) (*exec.Cmd, error) {
	edge := edgePath()
	if edge == "" {
		return nil, errors.New("не найден Microsoft Edge")
	}
	appProfilePrefs(profileDir)
	cmd := exec.Command(edge, "--app="+url, "--user-data-dir="+profileDir, fmt.Sprintf("--window-size=%d,%d", width, height),
		"--no-first-run", "--no-default-browser-check", "--disable-features=Translate", "--lang=ru",
		// no browser zoom or swipe-back gestures: the window is an app
		"--disable-pinch", "--overscroll-history-navigation=0")
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// appProfilePrefs turns off the browser features that make no sense in the
// VPNer window (offers to save passwords, autofill suggestions, translation)
// in its own Edge profile.
func appProfilePrefs(profileDir string) {
	p := filepath.Join(profileDir, "Default", "Preferences")
	prefs := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		if json.Unmarshal(b, &prefs) != nil {
			return // leave a file we cannot read alone
		}
	}
	set := func(path string, v any) {
		keys := strings.Split(path, ".")
		m := prefs
		for _, k := range keys[:len(keys)-1] {
			next, ok := m[k].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[k] = next
			}
			m = next
		}
		m[keys[len(keys)-1]] = v
	}
	set("credentials_enable_service", false)
	set("credentials_enable_autosignin", false)
	set("profile.password_manager_enabled", false)
	set("autofill.enabled", false)
	set("autofill.profile_enabled", false)
	set("autofill.credit_card_enabled", false)
	set("translate.enabled", false)
	b, err := json.Marshal(prefs)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(p), 0o700)
	os.WriteFile(p, b, 0o600)
}

// OpenVMConsole opens the Hyper-V console window of a VM.
func OpenVMConsole(vm string) error {
	return exec.Command(filepath.Join(os.Getenv("WINDIR"), "System32", "vmconnect.exe"), "localhost", vm).Start()
}

// AttachParentConsole makes CLI output visible when started from a terminal
// (the binary is built as a GUI application).
func AttachParentConsole() bool {
	k := windows.NewLazySystemDLL("kernel32.dll")
	r, _, _ := k.NewProc("AttachConsole").Call(uintptr(^uint32(0))) // ATTACH_PARENT_PROCESS
	if r == 0 {
		return false
	}
	if h, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE); err == nil && h != 0 {
		os.Stdout = os.NewFile(uintptr(h), "stdout")
	}
	if h, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE); err == nil && h != 0 {
		os.Stderr = os.NewFile(uintptr(h), "stderr")
	}
	return true
}

// Ask shows a native Yes/No question and reports whether Yes was chosen.
func Ask(title, text string) bool {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	r, _ := windows.MessageBox(0, m, t, windows.MB_YESNO|windows.MB_ICONQUESTION|windows.MB_SETFOREGROUND)
	return r == 6 // IDYES
}

// MessageBox shows a native dialog (used for fatal startup errors).
func MessageBox(title, text string, isError bool) {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(text)
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION)
	if isError {
		flags = windows.MB_OK | windows.MB_ICONERROR
	}
	windows.MessageBox(0, m, t, flags)
}
