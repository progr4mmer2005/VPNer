//go:build windows

// Package install puts VPNer on the computer (Program Files, shortcuts, the
// "Installed apps" entry) and removes it again.
package install

import (
	"vpner/internal/i18n"

	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"vpner/internal/firewall"
)

const (
	AppName = "VPNer"
	ExeName = "vpner.exe"
	regKey  = `Software\Microsoft\Windows\CurrentVersion\Uninstall\VPNer`
)

// Options are chosen in the setup wizard.
type Options struct {
	Dir       string `json:"dir"`
	Desktop   bool   `json:"desktop"`
	StartMenu bool   `json:"startMenu"`
	Autostart bool   `json:"autostart"`
	Launch    bool   `json:"launch"`
}

// Installed reports the folder and version of an existing installation.
func Installed() (dir, version string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", ""
	}
	defer k.Close()
	dir, _, _ = k.GetStringValue("InstallLocation")
	version, _, _ = k.GetStringValue("DisplayVersion")
	return dir, version
}

// DefaultDir is the existing installation folder or Program Files\VPNer.
func DefaultDir() string {
	if dir, _ := Installed(); dir != "" {
		return dir
	}
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	return filepath.Join(pf, AppName)
}

// DataDir is where VPNer keeps its settings (see cmd/vpner).
func DataDir() string {
	if d := os.Getenv("VPNER_DATA"); d != "" {
		return d
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), AppName)
}

// Install copies the program and registers it. step reports progress.
func Install(payload []byte, version string, o Options, step func(string)) error {
	dir := filepath.Clean(strings.TrimSpace(o.Dir))
	if dir == "." || !filepath.IsAbs(dir) {
		return errors.New(i18n.T("install.enterFullPathOfInstallation"))
	}
	if len(payload) == 0 {
		return errors.New(i18n.T("install.installerHasNoProgramInside"))
	}
	if Running() {
		step(i18n.T("install.closingRunningVpner"))
		if err := StopRunning(); err != nil {
			return err
		}
	}
	step(fmt.Sprintf(i18n.T("install.copyingProgramTo"), dir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf(i18n.T("install.installationFolder"), err)
	}
	exe := filepath.Join(dir, ExeName)
	tmp := exe + ".new"
	if err := os.WriteFile(tmp, payload, 0o755); err != nil {
		return fmt.Errorf(i18n.T("install.writingProgram"), err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf(i18n.T("install.replacingProgram"), err)
	}
	step(i18n.T("install.registeringInWindowsInstalledApps"))
	if err := register(dir, exe, version, len(payload)); err != nil {
		return err
	}
	if o.StartMenu {
		step(i18n.T("install.creatingStartMenuShortcut"))
		if err := shortcut(startMenuLink(), exe, dir); err != nil {
			return err
		}
	} else {
		os.Remove(startMenuLink())
	}
	if o.Desktop {
		step(i18n.T("install.creatingDesktopShortcut"))
		if err := shortcut(desktopLink(), exe, dir); err != nil {
			return err
		}
	} else {
		os.Remove(desktopLink())
	}
	step(i18n.T("install.settingUpAutostart"))
	if err := setAutostart(exe, o.Autostart); err != nil {
		return err
	}
	return nil
}

func register(dir, exe, version string, size int) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, regKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf(i18n.T("install.writingToRegistry"), err)
	}
	defer k.Close()
	for name, v := range map[string]string{
		"DisplayName": AppName, "DisplayVersion": version, "Publisher": AppName, "InstallLocation": dir,
		"DisplayIcon": exe + ",0", "UninstallString": `"` + exe + `" uninstall`, "QuietUninstallString": `"` + exe + `" uninstall`,
		"InstallDate": time.Now().Format("20060102"),
	} {
		if err := k.SetStringValue(name, v); err != nil {
			return err
		}
	}
	k.SetDWordValue("NoModify", 1)
	k.SetDWordValue("NoRepair", 1)
	k.SetDWordValue("EstimatedSize", uint32(size/1024))
	return nil
}

func knownFolder(id *windows.KNOWNFOLDERID) string {
	p, _ := windows.KnownFolderPath(id, 0)
	return p
}
func startMenuLink() string {
	return filepath.Join(knownFolder(windows.FOLDERID_CommonPrograms), AppName+".lnk")
}
func desktopLink() string {
	return filepath.Join(knownFolder(windows.FOLDERID_Desktop), AppName+".lnk")
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func hidden(cmd *exec.Cmd) *exec.Cmd {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

func shortcut(lnk, exe, dir string) error {
	script := fmt.Sprintf(`$s = (New-Object -ComObject WScript.Shell).CreateShortcut(%s); $s.TargetPath = %s; $s.WorkingDirectory = %s; $s.IconLocation = %s; $s.Description = 'VPNer — несколько VPN одновременно'; $s.Save()`,
		psq(lnk), psq(exe), psq(dir), psq(exe+",0"))
	if out, err := hidden(exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)).CombinedOutput(); err != nil {
		return fmt.Errorf(i18n.T("install.shortcut"), lnk, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// setAutostart mirrors winutil.SetAutostart for the installed executable.
func setAutostart(exe string, on bool) error {
	if !on {
		hidden(exec.Command("schtasks.exe", "/Delete", "/TN", AppName, "/F")).Run()
		return nil
	}
	out, err := hidden(exec.Command("schtasks.exe", "/Create", "/TN", AppName, "/TR", fmt.Sprintf(`"%s" --tray`, exe),
		"/SC", "ONLOGON", "/RL", "HIGHEST", "/F")).CombinedOutput()
	if err != nil {
		return fmt.Errorf(i18n.T("install.autostart"), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Running reports whether another vpner.exe is running.
func Running() bool { return len(otherProcesses()) > 0 }

func otherProcesses() []uint32 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snap)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	var pids []uint32
	self := uint32(os.Getpid())
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		if e.ProcessID != self && strings.EqualFold(windows.UTF16ToString(e.ExeFile[:]), ExeName) {
			pids = append(pids, e.ProcessID)
		}
	}
	return pids
}

// StopRunning asks a running VPNer to quit the regular way (VPNs are
// disconnected, the network is restored) and waits until it is gone.
func StopRunning() error {
	b, err := os.ReadFile(filepath.Join(DataDir(), "ui.json"))
	if err == nil {
		var ui struct {
			Port  int    `json:"port"`
			Token string `json:"token"`
		}
		if json.Unmarshal(b, &ui) == nil && ui.Port > 0 {
			req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:"+strconv.Itoa(ui.Port)+"/api/quit", nil)
			req.Header.Set("X-Token", ui.Token)
			if resp, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req); err == nil {
				resp.Body.Close()
			}
		}
	}
	for i := 0; i < 60; i++ {
		if !Running() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return errors.New(i18n.T("install.vpnerDidNotCloseClose"))
}

// Uninstall removes the program. removeData also deletes the settings and
// the WSL container.
func Uninstall(removeData bool) error {
	exe, _ := os.Executable()
	dir, _ := Installed()
	if Running() {
		if err := StopRunning(); err != nil {
			return err
		}
	}
	setAutostart("", false)
	os.Remove(startMenuLink())
	os.Remove(desktopLink())
	registry.DeleteKey(registry.LOCAL_MACHINE, regKey) // a 64-bit process sees the 64-bit view
	// a crash may have left the firewall kill switch behind
	if ks := (&firewall.KillSwitch{StateDir: DataDir()}); ks.Active() {
		ks.Disable()
	}
	if removeData {
		hidden(exec.Command("wsl.exe", "--unregister", "vpner")).Run()
		os.RemoveAll(DataDir())
	}
	// The running executable cannot delete itself: a short-lived cmd does it
	// once this process has exited. Only our own file and the then empty
	// folder are removed, never anything else in it.
	if dir == "" {
		dir = filepath.Dir(exe)
	}
	target := filepath.Join(dir, ExeName)
	if strings.EqualFold(filepath.Clean(exe), filepath.Clean(target)) {
		cmd := hidden(exec.Command("cmd.exe", "/C", fmt.Sprintf(`ping -n 3 127.0.0.1 >nul & del /f /q "%s" & rmdir "%s"`, target, dir)))
		return cmd.Start()
	}
	return nil
}
