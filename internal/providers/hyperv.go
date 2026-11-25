package providers

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"
	"regexp"
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

// hostnameRe: a Linux host name, which is also the device name a VPN program
// in the VM reports to its service.
var hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// VMAppIncy: VPNer installs INCY in the VM and sets it up (hyperv.AppIncy).
const VMAppIncy = "incy"

func (hypervProvider) Fields() []Field {
	return []Field{
		{Key: "app", Label: i18n.T("providers.vmApp"), Kind: "select", Default: "",
			Options: []Option{{Value: "", Label: i18n.T("providers.vmAppManual")}, {Value: VMAppIncy, Label: i18n.T("providers.vmAppIncy")}},
			Help:    i18n.T("providers.vmAppHelp")},
		{Key: "deviceName", Label: i18n.T("providers.vmDeviceName"), Kind: "text", Placeholder: "Incy-Home",
			Help: i18n.T("providers.vmDeviceNameHelp")},
		{Key: "subscription", Label: i18n.T("providers.vmAppSubscription"), Kind: "text", Secret: true,
			Placeholder: "https://…", Help: i18n.T("providers.vmAppSubscriptionHelp")},
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
	app := c.P("app")
	if app != "" && app != VMAppIncy {
		return nil, fmt.Errorf(i18n.T("providers.vmAppUnknown"), app)
	}
	host := c.P("deviceName")
	if host == "" && app != "" {
		return nil, errors.New(i18n.T("providers.vmDeviceNameRequired"))
	}
	if host != "" && !hostnameRe.MatchString(host) {
		return nil, fmt.Errorf(i18n.T("providers.vmDeviceNameInvalid"), host)
	}
	return &VMSpec{
		VMName:   "VPNer - " + c.ID,
		MemoryMB: atoiDefault(c.P("memory"), 3072, 1024, 65536),
		CPUs:     atoiDefault(c.P("cpus"), 2, 1, 64),
		DiskGB:   atoiDefault(c.P("disk"), 24, 8, 2048),
		// A program VPNer sets up itself has a window: it needs the desktop.
		Desktop:  boolDefault(c, "desktop", true) || c.P("app") != "",
		DNS:      dnsList(c),
		App:      app,
		Hostname: host,
	}, nil
}
