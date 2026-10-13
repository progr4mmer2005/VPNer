//go:build windows

package winutil

import (
	"os/exec"
	"sort"
	"strings"
)

// ForeignVPNs lists network adapters of other VPN programs that currently
// take over the default route. They fight with VPNer for traffic (and the
// AmneziaVPN/WireGuard clients additionally block other programs from
// reaching their server), so the user must be warned.
func ForeignVPNs() []string {
	script := `$phys = @(Get-NetAdapter -Physical -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1' -and $_.RouteMetric -lt 1000 } |
  ForEach-Object { $_.InterfaceAlias } |
  Where-Object { $_ -ne 'VPNer' -and $_ -notlike 'vEthernet*' -and $phys -notcontains $_ } |
  Sort-Object -Unique`
	out, err := hidden(exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"[Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)).Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	sort.Strings(names)
	return names
}
