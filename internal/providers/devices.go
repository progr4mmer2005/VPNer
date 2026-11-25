package providers

import "vpner/internal/config"

// Device kinds tell how a connection uses the places that VPN services
// limit: devices of a subscription, simultaneous sessions or connections,
// keys. The UI warns about them before and after every action that can
// take such a place (adding, importing, exporting a profile, chains). The
// web UI has the same table in deviceKind().
const (
	DeviceNone    = ""
	DeviceVMApp   = "vm-app"  // a VM with a VPN program VPNer sets up: a new device of its subscription
	DeviceVM      = "vm"      // a VM whose program is installed by hand: a device of that program's service
	DeviceLogin   = "login"   // a corporate VPN login: a session the server may limit
	DeviceKey     = "key"     // a WireGuard/AmneziaWG key: one key is one device
	DeviceUser    = "user"    // an Amnezia server: VPNer creates its own user there
	DeviceAccount = "account" // a share link or subscription: the service may limit devices or connections
)

// DeviceKind says how c can take a place in a VPN service's device limit.
func DeviceKind(c *config.Connection) string {
	switch c.Type {
	case "hyperv":
		if c.P("app") != "" {
			return DeviceVMApp
		}
		return DeviceVM
	case "openconnect", "openvpn":
		return DeviceLogin
	case "wireguard":
		return DeviceKey
	case "amnezia-server":
		return DeviceUser
	case "link", "mihomo", TypeSubscription:
		return DeviceAccount
	}
	return DeviceNone // chains (their hops count), proxies, interfaces
}
