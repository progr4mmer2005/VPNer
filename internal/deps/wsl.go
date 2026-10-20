package deps

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"vpner/internal/assets"
	"vpner/internal/bridge"
	"vpner/internal/wslhost"
)

// wslConf hardens the dedicated distro: no Windows drive mounts, no running
// Windows programs from Linux, no systemd. Only the agent lives here.
const wslConf = `[boot]
systemd=false

[automount]
enabled=false
mountFsTab=false

[interop]
enabled=false
appendWindowsPath=false

[user]
default=root
`

// WSLStatus describes what is missing.
type WSLStatus struct {
	WSLInstalled bool   `json:"wslInstalled"`
	DistroExists bool   `json:"distroExists"`
	Detail       string `json:"detail,omitempty"`
}

func CheckWSL() WSLStatus {
	st := WSLStatus{}
	if err := wslhost.Available(); err != nil {
		st.Detail = err.Error()
		return st
	}
	st.WSLInstalled = true
	st.DistroExists = wslhost.DistroExists(wslhost.DistroName)
	return st
}

// InstallWSL enables the WSL platform itself (needs admin and a reboot).
func InstallWSL() (string, error) {
	cmd := exec.Command("wsl.exe", "--install", "--no-distribution")
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(strings.ReplaceAll(string(out), "\x00", ""))
	if err != nil {
		return s, fmt.Errorf(i18n.T("deps.installingWsl"), err, s)
	}
	return s, nil
}

// EnsureDistro imports the dedicated distro (if needed), hardens it and
// installs the current agent binary.
func EnsureDistro(dataDir, cacheDir string, progress Progress) error {
	if err := wslhost.Available(); err != nil {
		return fmt.Errorf(i18n.T("deps.wslCanBeInstalledWith"), err)
	}
	name := wslhost.DistroName
	if !wslhost.DistroExists(name) {
		a, err := Alpine()
		if err != nil {
			return err
		}
		rootfs, err := Fetch(a, cacheDir, progress)
		if err != nil {
			return err
		}
		if progress != nil {
			progress(i18n.T("deps.creatingWslContainer"), 0, -1)
		}
		if err := wslhost.Import(name, filepath.Join(dataDir, "wsl"), rootfs); err != nil {
			return err
		}
	}
	cur, _ := wslhost.Run(name, nil, "/bin/cat", "/etc/wsl.conf")
	if strings.TrimSpace(cur) != strings.TrimSpace(wslConf) {
		if err := wslhost.WriteFile(name, "/etc/wsl.conf", []byte(wslConf), "644"); err != nil {
			return fmt.Errorf(i18n.T("deps.settingUpContainer"), err)
		}
		wslhost.Terminate(name) // apply wsl.conf on next start
	}
	bin, sum, err := assets.Agent("")
	if err != nil {
		return err
	}
	have, _ := wslhost.Run(name, nil, "/bin/cat", "/opt/vpner/agent.sha256")
	if strings.TrimSpace(have) != sum {
		if progress != nil {
			progress(i18n.T("deps.installingAgentIntoContainer"), 0, -1)
		}
		if err := wslhost.WriteFile(name, wslhost.AgentPath, bin, "755"); err != nil {
			return fmt.Errorf(i18n.T("deps.installingAgent"), err)
		}
		if err := wslhost.WriteFile(name, "/opt/vpner/agent.sha256", []byte(sum+"\n"), "644"); err != nil {
			return err
		}
	}
	return nil
}

// EnsurePackages installs Alpine packages through the live agent session.
// Downloads travel over the bridge, so this works even when WSL networking is
// blocked.
func EnsurePackages(s *wslhost.Session, pkgs []string, progress Progress) error {
	pkgs = append([]string(nil), pkgs...)
	sort.Strings(pkgs)
	want := strings.Join(pkgs, " ")
	var res bridge.ExecResult
	if err := s.Call("exec", bridge.ExecParams{Argv: []string{"/bin/cat", "/opt/vpner/packages.txt"}}, &res); err == nil && res.Code == 0 && strings.TrimSpace(res.Output) == want {
		return nil
	}
	if progress != nil {
		progress(fmt.Sprintf(i18n.T("deps.installingPackagesIntoContainer"), want), 0, -1)
	}
	env := map[string]string{
		"http_proxy": "http://127.0.0.1:3128", "https_proxy": "http://127.0.0.1:3128",
		"HTTP_PROXY": "http://127.0.0.1:3128", "HTTPS_PROXY": "http://127.0.0.1:3128",
	}
	args := append([]string{"/sbin/apk", "add", "--no-cache", "--no-progress"}, pkgs...)
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		res = bridge.ExecResult{}
		if err := s.Call("exec", bridge.ExecParams{Argv: args, Env: env}, &res); err != nil {
			last = err
			continue
		}
		if res.Code == 0 {
			last = nil
			break
		}
		last = errors.New(lastLines(res.Output, 8))
	}
	if last != nil {
		return fmt.Errorf(i18n.T("deps.couldNotInstallPackages"), want, last)
	}
	return s.Call("exec", bridge.ExecParams{Argv: []string{"/bin/sh", "-c", "mkdir -p /opt/vpner && cat > /opt/vpner/packages.txt"}, Stdin: want + "\n"}, nil)
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}
