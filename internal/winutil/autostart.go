//go:build windows

package winutil

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const taskName = "VPNer"

// SetAutostart registers (or removes) a logon task that starts VPNer with
// administrator rights without a UAC prompt.
func SetAutostart(on bool) error {
	if !on {
		out, err := hidden(exec.Command("schtasks.exe", "/Delete", "/TN", taskName, "/F")).CombinedOutput()
		if err != nil && !strings.Contains(string(out), "cannot find") && !strings.Contains(string(out), "не удается найти") {
			return nil // already absent
		}
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := hidden(exec.Command("schtasks.exe", "/Create", "/TN", taskName, "/TR", fmt.Sprintf(`"%s" --tray`, exe),
		"/SC", "ONLOGON", "/RL", "HIGHEST", "/F")).CombinedOutput()
	if err != nil {
		return fmt.Errorf("не удалось включить автозапуск: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func AutostartEnabled() bool {
	return hidden(exec.Command("schtasks.exe", "/Query", "/TN", taskName)).Run() == nil
}
