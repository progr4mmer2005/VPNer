package providers

import (
	"vpner/internal/i18n"

	"strconv"

	"vpner/internal/config"
)

// A dedicated Hyper-V virtual machine running the original desktop VPN
// application. VPNer creates and configures the VM automatically.
type hypervProvider struct{}

func init() { Register(hypervProvider{}) }

func (hypervProvider) Type() string     { return "hyperv" }
func (hypervProvider) Title() string    { return i18n.T("providers.virtualMachineForVpnProgram") }
func (hypervProvider) Runtime() Runtime { return RuntimeVM }
func (hypervProvider) Description() string {
	return i18n.T("providers.separateHyperVVirtualMachine")
}

func (hypervProvider) Fields() []Field {
	return []Field{
		{Key: "memory", Label: i18n.T("providers.vmMemoryMb"), Kind: "number", Default: "3072", Help: i18n.T("providers.2048IsMinimumForDesktop")},
		{Key: "cpus", Label: i18n.T("providers.processors"), Kind: "number", Default: "2"},
		{Key: "desktop", Label: i18n.T("providers.desktopAndBrowser"), Kind: "bool", Default: "true", Help: i18n.T("providers.neededForGraphicalVpnPrograms")},
		{Key: "disk", Label: i18n.T("providers.diskSizeGb"), Kind: "number", Default: "24", Advanced: true},
		fieldFallbackDNS(),
	}
}

func atoiDefault(s string, def, minv, maxv int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return max(minv, min(maxv, n))
}

func (hypervProvider) VM(c *config.Connection) (*VMSpec, error) {
	return &VMSpec{
		VMName:   "VPNer - " + c.ID,
		MemoryMB: atoiDefault(c.P("memory"), 3072, 1024, 65536),
		CPUs:     atoiDefault(c.P("cpus"), 2, 1, 64),
		DiskGB:   atoiDefault(c.P("disk"), 24, 8, 2048),
		Desktop:  boolDefault(c, "desktop", true),
		DNS:      dnsList(c),
	}, nil
}
