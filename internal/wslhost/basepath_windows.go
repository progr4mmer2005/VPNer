//go:build windows

package wslhost

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// BasePath is the folder WSL keeps a distro's disk in ("" when unknown).
func BasePath(name string) string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Lxss`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer k.Close()
	subs, _ := k.ReadSubKeyNames(-1)
	for _, s := range subs {
		d, err := registry.OpenKey(k, s, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		n, _, _ := d.GetStringValue("DistributionName")
		p, _, _ := d.GetStringValue("BasePath")
		d.Close()
		if strings.EqualFold(n, name) {
			return strings.TrimPrefix(p, `\?\`)
		}
	}
	return ""
}
