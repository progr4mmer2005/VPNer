//go:build windows

// Package hyperv creates and runs the gateway virtual machines used for VPN
// applications that only exist as desktop programs (the original AmneziaVPN,
// Cisco Secure Client, vendor clients...). Each VM gets:
//
//   - a WAN NIC on an external Hyper-V switch: the VPN app inside reaches its
//     server directly, bypassing the host network stack entirely;
//   - a LAN NIC on the internal "VPNer-LAN" switch: only the host talks to
//     the SOCKS5 gateway there;
//   - a gateway service whose traffic nftables confines to the VPN tunnel.
package hyperv

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	LANSwitch = "VPNer-LAN"
	LANAlias  = "vEthernet (VPNer-LAN)"
	LANHost   = "10.211.0.1"
	LANPrefix = "10.211.0."
	WANSwitch = "VPNer-WAN"
)

func ps(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
		"$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		return s, fmt.Errorf("%v: %s", err, lastLines(s, 6))
	}
	return s, nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}

func q(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// Available checks that Hyper-V and its PowerShell module are usable.
func Available() error {
	out, err := ps(`if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { 'nomodule' } elseif ((Get-Service vmms -ErrorAction SilentlyContinue).Status -ne 'Running') { 'noservice' } else { 'ok' }`)
	if err != nil {
		return err
	}
	switch out {
	case "ok":
		return nil
	case "nomodule":
		return errors.New("Hyper-V не включён. Нажмите «Включить Hyper-V» в настройках (нужна Windows Pro/Enterprise и перезагрузка)")
	default:
		return errors.New("служба Hyper-V (vmms) не запущена — перезагрузите компьютер после включения Hyper-V")
	}
}

// Enable turns on the Hyper-V feature (reboot required).
func Enable() (string, error) {
	return ps(`$r = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart; if ($r.RestartNeeded) { 'restart' } else { 'ok' }`)
}

// EnsureLAN creates the internal switch and gives the host its address.
func EnsureLAN() error {
	_, err := ps(fmt.Sprintf(`
if (-not (Get-VMSwitch -Name %[1]s -ErrorAction SilentlyContinue)) { New-VMSwitch -Name %[1]s -SwitchType Internal | Out-Null; Start-Sleep 2 }
$if = Get-NetAdapter -Name %[2]s
if (-not (Get-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress %[3]s -ErrorAction SilentlyContinue)) {
  Get-NetIPAddress -InterfaceIndex $if.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false
  New-NetIPAddress -InterfaceIndex $if.ifIndex -IPAddress %[3]s -PrefixLength 24 | Out-Null
}
try { Set-NetConnectionProfile -InterfaceIndex $if.ifIndex -NetworkCategory Private } catch {}
`, q(LANSwitch), q(LANAlias), q(LANHost)))
	if err != nil {
		return fmt.Errorf("внутренняя сеть VPNer-LAN: %w", err)
	}
	return nil
}

// EnsureWAN returns an external switch for the VMs' own internet access,
// creating one on the physical adapter if none exists.
func EnsureWAN(logf func(string)) (string, error) {
	name, err := ps(`$s = Get-VMSwitch -SwitchType External -ErrorAction SilentlyContinue | Select-Object -First 1; if ($s) { $s.Name } else { '' }`)
	if err != nil {
		return "", err
	}
	if name != "" {
		return name, nil
	}
	if logf != nil {
		logf("создаю внешний коммутатор Hyper-V для выхода виртуалок в интернет (сеть на пару секунд пропадёт)")
	}
	out, err := ps(fmt.Sprintf(`
$a = Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' } | Where-Object { Get-NetIPConfiguration -InterfaceIndex $_.ifIndex | Where-Object { $_.IPv4DefaultGateway } } | Sort-Object { $_.MediaType -ne '802.3' } | Select-Object -First 1
if (-not $a) { 'none' } else { New-VMSwitch -Name %s -NetAdapterName $a.Name -AllowManagementOS $true | Out-Null; 'ok' }`, q(WANSwitch)))
	if err != nil {
		return "", fmt.Errorf("внешний коммутатор: %w", err)
	}
	if out == "none" {
		if logf != nil {
			logf("подходящий физический адаптер не найден — виртуалки будут выходить через Default Switch (NAT)")
		}
		return "Default Switch", nil
	}
	return WANSwitch, nil
}

// VMConfig describes a VM to create.
type VMConfig struct {
	Name     string
	Dir      string
	MemoryMB int
	CPUs     int
	DiskGB   int
	WAN      string // switch name
	WANMac   string // 12 hex digits
	LANMac   string
	SeedDir  string // files for the cloud-init seed disk
}

func Exists(name string) bool {
	out, err := ps(fmt.Sprintf(`if (Get-VM -Name %s -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`, q(name)))
	return err == nil && out == "yes"
}

// Create builds the VM from the base image and a cloud-init seed disk.
func Create(base string, c VMConfig) error {
	if err := os.MkdirAll(c.Dir, 0o755); err != nil {
		return err
	}
	_, err := ps(fmt.Sprintf(`
$name=%[1]s; $dir=%[2]s; $base=%[3]s; $seedSrc=%[4]s
$disk = Join-Path $dir 'disk.vhdx'; $seed = Join-Path $dir 'seed.vhdx'
if (Test-Path $disk) { Remove-Item $disk -Force }
if (Test-Path $seed) { Remove-Item $seed -Force }
Convert-VHD -Path $base -DestinationPath $disk -VHDType Dynamic
Resize-VHD -Path $disk -SizeBytes (%[5]d * 1GB)
New-VHD -Path $seed -SizeBytes 128MB -Dynamic | Out-Null
$d = Mount-VHD -Path $seed -Passthru | Initialize-Disk -PartitionStyle MBR -PassThru
try {
  $p = New-Partition -DiskNumber $d.Number -UseMaximumSize -AssignDriveLetter:$false
  Format-Volume -Partition $p -FileSystem FAT32 -NewFileSystemLabel CIDATA -Confirm:$false | Out-Null
  $mp = Join-Path $env:TEMP ('vpner-seed-' + [guid]::NewGuid())
  New-Item -ItemType Directory $mp | Out-Null
  Add-PartitionAccessPath -DiskNumber $d.Number -PartitionNumber $p.PartitionNumber -AccessPath $mp
  Copy-Item -Path (Join-Path $seedSrc '*') -Destination $mp
  Remove-PartitionAccessPath -DiskNumber $d.Number -PartitionNumber $p.PartitionNumber -AccessPath $mp
  Remove-Item $mp
} finally { Dismount-VHD -Path $seed }
New-VM -Name $name -Generation 1 -MemoryStartupBytes (%[6]d * 1MB) -VHDPath $disk -Path $dir -SwitchName %[8]s | Out-Null
Set-VM -Name $name -ProcessorCount %[7]d -CheckpointType Disabled -AutomaticStartAction Nothing -AutomaticStopAction Save -Notes 'Создано VPNer: шлюз для VPN-программы. Удаляйте через VPNer.'
Set-VMMemory -VMName $name -DynamicMemoryEnabled $false
Get-VMNetworkAdapter -VMName $name | Set-VMNetworkAdapter -StaticMacAddress %[9]s
Get-VMNetworkAdapter -VMName $name | Rename-VMNetworkAdapter -NewName 'WAN'
Add-VMNetworkAdapter -VMName $name -SwitchName %[11]s -Name 'LAN' -StaticMacAddress %[10]s
Add-VMHardDiskDrive -VMName $name -ControllerType IDE -ControllerNumber 0 -ControllerLocation 1 -Path $seed
Enable-VMIntegrationService -VMName $name -Name 'Guest Service Interface' -ErrorAction SilentlyContinue
`, q(c.Name), q(c.Dir), q(base), q(c.SeedDir), c.DiskGB, c.MemoryMB, c.CPUs, q(c.WAN), q(c.WANMac), q(c.LANMac), q(LANSwitch)))
	if err != nil {
		return fmt.Errorf("создание виртуальной машины: %w", err)
	}
	return nil
}

// State returns the Hyper-V state: Running, Off, Saved, Paused, Starting...
func State(name string) (string, error) {
	return ps(fmt.Sprintf(`(Get-VM -Name %s).State.ToString()`, q(name)))
}

func Start(name string) error {
	_, err := ps(fmt.Sprintf(`Start-VM -Name %s`, q(name)))
	return err
}

// Save suspends the VM to disk (fast resume, VPN app state is kept).
func Save(name string) error {
	_, err := ps(fmt.Sprintf(`$v = Get-VM -Name %s -ErrorAction SilentlyContinue; if ($v -and $v.State -eq 'Running') { Save-VM -VM $v }`, q(name)))
	return err
}

func Remove(name, dir string) error {
	_, err := ps(fmt.Sprintf(`$v = Get-VM -Name %s -ErrorAction SilentlyContinue
if ($v) { if ($v.State -ne 'Off') { Stop-VM -VM $v -TurnOff -Force }; Remove-VM -VM $v -Force }`, q(name)))
	if err != nil {
		return err
	}
	if dir != "" {
		return os.RemoveAll(dir)
	}
	return nil
}

// NewMAC returns a random MAC in the Hyper-V range (00-15-5D), as 12 hex digits.
func NewMAC() string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("00155D%02X%02X%02X", b[0], b[1], b[2])
}

// MACColon formats 12 hex digits as aa:bb:cc:dd:ee:ff for Linux.
func MACColon(m string) string {
	m = strings.ToLower(m)
	var parts []string
	for i := 0; i+2 <= len(m); i += 2 {
		parts = append(parts, m[i:i+2])
	}
	return strings.Join(parts, ":")
}

func OpenConsole(name string) error {
	return exec.Command(filepath.Join(os.Getenv("WINDIR"), "System32", "vmconnect.exe"), "localhost", name).Start()
}
