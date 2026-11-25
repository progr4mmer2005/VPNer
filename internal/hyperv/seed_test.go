//go:build windows

package hyperv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type userData struct {
	WriteFiles []struct {
		Path        string `yaml:"path"`
		Permissions string `yaml:"permissions"`
		Content     string `yaml:"content"`
	} `yaml:"write_files"`
	Runcmd [][]string `yaml:"runcmd"`
}

func readSeed(t *testing.T, app string) userData {
	dir := t.TempDir()
	err := WriteSeed(dir, SeedConfig{ID: "t", Hostname: "vpner-t", LANIP: "10.77.0.10", WANMac: "00:15:5d:00:00:01",
		LANMac: "00:15:5d:00:00:02", GatewayUser: "vpner", GatewayPass: "p", ConsolePass: "c", Desktop: true,
		Agent: []byte("agent"), App: app})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "user-data"))
	if err != nil {
		t.Fatal(err)
	}
	var u userData
	if err := yaml.Unmarshal(b, &u); err != nil {
		t.Fatalf("user-data is not valid YAML: %v\n%s", err, b)
	}
	return u
}

func fileOf(u userData, path string) (string, bool) {
	for _, f := range u.WriteFiles {
		if f.Path == path {
			return f.Content, true
		}
	}
	return "", false
}

// The files reach the VM unchanged, and the setup installs INCY after the
// desktop.
func TestSeedIncy(t *testing.T) {
	u := readSeed(t, AppIncy)
	want, _, _ := appFiles(AppIncy)
	want = append(want, desktopFiles()...)
	want = append(want, seedFile{"/etc/systemd/system/vpner-setup.service", "0644", setupUnit})
	for _, w := range want {
		found := false
		for _, f := range u.WriteFiles {
			if f.Path == w.Path {
				found = true
				if f.Content != w.Content {
					t.Errorf("%s changed on the way:\n%q\nwant\n%q", w.Path, f.Content, w.Content)
				}
				if f.Permissions != w.Mode {
					t.Errorf("%s permissions %s, want %s", w.Path, f.Permissions, w.Mode)
				}
			}
		}
		if !found {
			t.Errorf("%s is missing", w.Path)
		}
	}
	script, ok := fileOf(u, "/usr/local/sbin/vpner-setup")
	if !ok {
		t.Fatal("no setup script")
	}
	desktop := strings.Index(script, "restart lightdm")
	install := strings.Index(script, "/usr/local/sbin/vpner-incy-install")
	if desktop < 0 || install < desktop {
		t.Errorf("INCY must be installed after the desktop: desktop %d, install %d", desktop, install)
	}
	if !strings.Contains(incyInstall, incySHA256) || !strings.Contains(incyInstall, "sha256sum -c") {
		t.Error("the package must be checked by SHA-256")
	}
	if !strings.Contains(incyInstall, "-C -") {
		t.Error("the download must resume where it stopped")
	}
	// the setup runs as a service, started by cloud-init, retried on failure
	started := false
	for _, c := range u.Runcmd {
		if strings.Contains(strings.Join(c, " "), "start --no-block vpner-setup.service") {
			started = true
		}
	}
	if !started {
		t.Error("cloud-init must start vpner-setup.service")
	}
	if !strings.Contains(setupUnit, "Restart=on-failure") || !strings.Contains(setupUnit, "ConditionPathExists=!/var/lib/vpner/setup-ok") {
		t.Error("the setup must be retried until it succeeds once")
	}
}

// Without an app the seed has no app files and the setup installs none.
func TestSeedNoApp(t *testing.T) {
	u := readSeed(t, "")
	for _, f := range u.WriteFiles {
		if strings.Contains(f.Path, "incy") {
			t.Errorf("unexpected %s", f.Path)
		}
	}
	script, _ := fileOf(u, "/usr/local/sbin/vpner-setup")
	if strings.Contains(script, "incy") {
		t.Error("the setup installs an app that was not chosen")
	}
}

// Lessons from Debian 13 on Hyper-V: each of these broke the VM setup.
func TestSetupDebian13(t *testing.T) {
	script := setupScript(true, AppIncy)
	for _, p := range desktopPackages {
		// gone in Debian 13: apt installed nothing because of it
		if p == "policykit-1" {
			t.Error("policykit-1 is not in Debian 13; use polkitd")
		}
	}
	// every apt-get waits for the dpkg lock (unattended-upgrades at first boot)
	for _, s := range []string{script, incyInstall} {
		for _, line := range strings.Split(s, "\n") {
			if strings.Contains(line, "apt-get") && !strings.Contains(line, "Lock::Timeout") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				t.Errorf("apt-get without a lock timeout: %s", line)
			}
		}
	}
	if !strings.Contains(script, "apt-cache show") {
		t.Error("packages missing from the repository must be skipped, not abort the install")
	}
	files := map[string]string{}
	for _, f := range desktopFiles() {
		files[f.Path] = f.Content
	}
	if !strings.Contains(files["/etc/X11/xorg.conf.d/10-vpner-hyperv.conf"], `Driver "modesetting"`) {
		t.Error("Xorg needs a Device section for the Hyper-V video card")
	}
	if !strings.Contains(files["/etc/modprobe.d/vpner-hyperv-video.conf"], "blacklist vga16fb") ||
		!strings.Contains(files["/etc/systemd/system/lightdm.service.d/vpner.conf"], "rmmod vga16fb") {
		t.Error("vga16fb must be kept away from Xorg")
	}
	if !strings.Contains(files["/etc/lightdm/lightdm.conf.d/50-vpner.conf"], "autologin-user=vpner") {
		t.Error("no autologin")
	}
	// the state the agent reports, with the reasons VPNer can show
	for _, code := range []string{SetupErrPackages, SetupErrGateway, SetupErrDesktop, SetupErrAppPackages, SetupErrAppDownload, SetupErrAppInstall} {
		if !strings.Contains(script, "fail "+code) {
			t.Errorf("the setup never reports %q", code)
		}
	}
	if !strings.Contains(script, "state done") || !strings.Contains(script, "setup-ok") {
		t.Error("the setup must mark its success")
	}
}

// The subscription link is never written to the setup disk.
func TestSeedHasNoSubscription(t *testing.T) {
	u := readSeed(t, AppIncy)
	for _, f := range u.WriteFiles {
		if strings.Contains(f.Content, "https://") && !strings.Contains(f.Content, incyURL) {
			t.Errorf("%s holds a link", f.Path)
		}
	}
}

// The scripts parse (sh -n only reads them); skipped without a shell.
func TestIncyScriptsParse(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	files, _, _ := appFiles(AppIncy)
	files = append(files, seedFile{"/usr/local/sbin/vpner-setup", "0755", setupScript(true, AppIncy)})
	for _, f := range files {
		if !strings.HasPrefix(f.Content, "#!/bin/sh") {
			continue
		}
		p := filepath.Join(t.TempDir(), "s.sh")
		if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(sh, "-n", p).CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", f.Path, err, out)
		}
	}
}

// INCY that cannot start its core is restarted with its helper: the session
// script watches the log, and polkit lets it run only VPNer's reset script.
func TestIncyReset(t *testing.T) {
	files, _, _ := appFiles(AppIncy)
	have := false
	for _, f := range files {
		if f.Path == incyResetPath && f.Mode == "0755" && strings.Contains(f.Content, "incy-worker") {
			have = true
		}
	}
	if !have {
		t.Fatal("no reset script")
	}
	if !strings.Contains(incyPolkit, `action.lookup("program") == "`+incyResetPath+`"`) {
		t.Error("polkit does not allow exactly the reset script")
	}
	for _, s := range []string{"core startup failed", "pkexec " + incyResetPath, "pause=$((pause * 2))"} {
		if !strings.Contains(incySession, s) {
			t.Errorf("session script lacks %q", s)
		}
	}
}
