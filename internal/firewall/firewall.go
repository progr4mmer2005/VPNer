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

// bootTask is a scheduled task that lifts a kill switch left behind when
// Windows went down with VPNer still running (power loss, a crash, a
// shutdown that did not wait for it). The rules live in Windows Firewall and
// survive a reboot: without the task the PC would stay offline until VPNer
// is started again.
const bootTask = "VPNer Network Restore"

// PowerShell helpers that turn a backed-up profile value into a
// Set-NetFirewallProfile argument (the backup keeps them as numbers).
const psProfileValues = `function OutAct($v) { switch ([string]$v) { '2' {'Allow'} '4' {'Block'} 'Allow' {'Allow'} 'Block' {'Block'} default {'NotConfigured'} } }
function OnState($v) { switch ([string]$v) { '1' {'True'} 'True' {'True'} '0' {'False'} 'False' {'False'} default {'NotConfigured'} } }
`

// bootScript is what the task runs as SYSTEM, at startup and at logon (with
// Fast Startup a shutdown is a hibernation and the startup trigger does not
// fire). The original policy is filled in when the kill switch goes on, so
// the task reads nothing from the user's folder. It acts only if our rules
// are still there, then removes itself.
const bootScript = `$g='VPNer Kill Switch'
if (Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue) {
  Set-NetFirewallProfile -Name Domain -DefaultOutboundAction {{Domain.out}} -Enabled {{Domain.on}}
  Set-NetFirewallProfile -Name Private -DefaultOutboundAction {{Private.out}} -Enabled {{Private.on}}
  Set-NetFirewallProfile -Name Public -DefaultOutboundAction {{Public.out}} -Enabled {{Public.on}}
  Get-NetFirewallRule -Group $g | Remove-NetFirewallRule
}
Unregister-ScheduledTask -TaskName 'VPNer Network Restore' -Confirm:$false
`

const bootTaskFailed = "BOOT-TASK-FAILED:"

const unregisterBootTask = "Get-ScheduledTask -TaskName '" + bootTask + "' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false"

// BootRestoreError means the kill switch is on, but the task that would lift
// it after an unexpected restart could not be set up.
type BootRestoreError struct{ Msg string }

func (e *BootRestoreError) Error() string { return e.Msg }

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
// network directly (the engine and VPNer itself). restoreAtBoot sets up the
// task that lifts the rules if Windows restarts before VPNer turns them off;
// a failure there is returned as *BootRestoreError with the kill switch on.
func (k *KillSwitch) Enable(programs []string, allowLAN, restoreAtBoot bool) error {
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
	if restoreAtBoot {
		b.WriteString(bootTaskScript(k.backupPath()))
	} else {
		b.WriteString("try { " + unregisterBootTask + " } catch {}\n")
	}
	out, err := ps(b.String())
	if err != nil {
		k.Disable()
		return fmt.Errorf(i18n.T("firewall.couldNotTurnOnSystem"), err)
	}
	for _, line := range strings.Split(out, "\n") {
		if msg, ok := strings.CutPrefix(strings.TrimSpace(line), bootTaskFailed); ok {
			return &BootRestoreError{Msg: strings.TrimSpace(msg)}
		}
	}
	return nil
}

// bootTaskScript registers bootTask with the original policy from the backup
// filled in. Its failure must not keep the kill switch off, so it is printed
// instead of stopping the script.
func bootTaskScript(backup string) string {
	return psProfileValues + fmt.Sprintf(`try {
  $r = %s
  $b = Get-Content -Raw -Path %s | ConvertFrom-Json
  foreach ($x in @($b)) {
    if (@('Domain','Private','Public') -notcontains [string]$x.Name) { continue }
    $r = $r.Replace('{{' + $x.Name + '.out}}', (OutAct $x.DefaultOutboundAction)).Replace('{{' + $x.Name + '.on}}', (OnState $x.Enabled))
  }
  $r = $r -replace '\{\{\w+\.(out|on)\}\}', 'NotConfigured'
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($r))
  $act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $enc)
  $trg = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
  $who = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
  Register-ScheduledTask -TaskName %s -Description 'Restores Windows Firewall if VPNer could not turn its kill switch off before Windows restarted.' -Action $act -Trigger $trg -Principal $who -Settings $set -Force | Out-Null
} catch { [Console]::Out.WriteLine(%s + $_.Exception.Message) }
`, psq(bootScript), psq(backup), psq(bootTask), psq(bootTaskFailed))
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
	// The policy goes first: it is what brings the network back, and when
	// Windows is shutting down there may be no time for the rest.
	script := psProfileValues + fmt.Sprintf(`$g=%s; $p=%s;
if (Test-Path $p) {
  $b = Get-Content -Raw -Path $p | ConvertFrom-Json
  foreach ($x in @($b)) {
    Set-NetFirewallProfile -Name $x.Name -DefaultOutboundAction (OutAct $x.DefaultOutboundAction) -Enabled (OnState $x.Enabled)
  }
} else {
  Set-NetFirewallProfile -All -DefaultOutboundAction Allow
}
Get-NetFirewallRule -Group $g -ErrorAction SilentlyContinue | Remove-NetFirewallRule
try { %s } catch {}
`, psq(group), psq(k.backupPath()), unregisterBootTask)
	if _, err := ps(script); err != nil {
		return fmt.Errorf(i18n.T("firewall.couldNotRestoreWindowsFirewall"), err)
	}
	os.Remove(k.backupPath())
	return nil
}
