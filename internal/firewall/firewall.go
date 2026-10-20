//go:build windows

// Package firewall implements the system-wide kill switch with Windows
// Firewall: while active, outbound traffic is blocked by default and only
// allowed for VPNer's own processes and for packets leaving through the TUN
// adapter. If the routing engine dies, nothing can leak around it.
package firewall

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const group = "VPNer Kill Switch"

// Addresses of the mihomo TUN adapter (mihomo defaults).
var tunAddrs = []string{"198.18.0.0/30", "fdfe:dcba:9876::/126"}

type KillSwitch struct {
	StateDir string
}

func (k *KillSwitch) backupPath() string { return filepath.Join(k.StateDir, "firewall-backup.json") }

// Active reports whether a kill switch is (or was left) in place.
func (k *KillSwitch) Active() bool {
	_, err := os.Stat(k.backupPath())
	return err == nil
}

func ps(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Enable installs the rules. programs are executables that may talk to the
// network directly (the engine and VPNer itself).
func (k *KillSwitch) Enable(programs []string, allowLAN bool) error {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New(i18n.T("firewall.systemKillSwitchNeedsAdministrator"))
	}
	os.MkdirAll(k.StateDir, 0o700)
	var b strings.Builder
	b.WriteString(fmt.Sprintf("$g=%s;\n", psq(group)))
	// back up the original policy only once (a crash may have left ours behind)
	if !k.Active() {
		b.WriteString(fmt.Sprintf("Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction | ConvertTo-Json | Set-Content -Encoding UTF8 -Path %s;\n", psq(k.backupPath())))
	}
	b.WriteString("Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule;\n")
	for _, p := range programs {
		b.WriteString(fmt.Sprintf("New-NetFirewallRule -Group $g -DisplayName ('VPNer: '+%s) -Direction Outbound -Action Allow -Program %s | Out-Null;\n", psq(filepath.Base(p)), psq(p)))
	}
	b.WriteString(fmt.Sprintf("New-NetFirewallRule -Group $g -DisplayName 'VPNer: TUN' -Direction Outbound -Action Allow -LocalAddress %s | Out-Null;\n", psqList(tunAddrs)))
	b.WriteString("New-NetFirewallRule -Group $g -DisplayName 'VPNer: DHCP' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null;\n")
	b.WriteString("New-NetFirewallRule -Group $g -DisplayName 'VPNer: DHCPv6/ND' -Direction Outbound -Action Allow -Protocol UDP -LocalPort 546 -RemotePort 547 | Out-Null;\n")
	if allowLAN {
		b.WriteString("New-NetFirewallRule -Group $g -DisplayName 'VPNer: LAN' -Direction Outbound -Action Allow -RemoteAddress LocalSubnet | Out-Null;\n")
	}
	b.WriteString("Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block;\n")
	if _, err := ps(b.String()); err != nil {
		k.Disable()
		return fmt.Errorf(i18n.T("firewall.couldNotTurnOnSystem"), err)
	}
	return nil
}

func psqList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = psq(s)
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// Disable restores the original firewall policy and removes our rules.
func (k *KillSwitch) Disable() error {
	script := fmt.Sprintf(`$g=%s; $p=%s;
if (Test-Path $p) {
  $b = Get-Content -Raw -Path $p | ConvertFrom-Json
  foreach ($x in @($b)) {
    $act = switch ([string]$x.DefaultOutboundAction) { '2' {'Allow'} '4' {'Block'} 'Allow' {'Allow'} 'Block' {'Block'} default {'NotConfigured'} }
    $en = switch ([string]$x.Enabled) { '1' {'True'} 'True' {'True'} '0' {'False'} 'False' {'False'} default {'NotConfigured'} }
    Set-NetFirewallProfile -Name $x.Name -DefaultOutboundAction $act -Enabled $en
  }
} else {
  Set-NetFirewallProfile -All -DefaultOutboundAction Allow
}
Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule
`, psq(group), psq(k.backupPath()))
	if _, err := ps(script); err != nil {
		return fmt.Errorf(i18n.T("firewall.couldNotRestoreWindowsFirewall"), err)
	}
	os.Remove(k.backupPath())
	return nil
}
