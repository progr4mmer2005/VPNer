package providers

import (
	"testing"

	"vpner/internal/config"
)

func TestDeviceKind(t *testing.T) {
	for _, tc := range []struct {
		c    config.Connection
		want string
	}{
		{config.Connection{Type: "hyperv", Params: map[string]string{"app": "incy"}}, DeviceVMApp},
		{config.Connection{Type: "hyperv"}, DeviceVM},
		{config.Connection{Type: "openconnect"}, DeviceLogin},
		{config.Connection{Type: "openvpn"}, DeviceLogin},
		{config.Connection{Type: "wireguard"}, DeviceKey},
		{config.Connection{Type: "amnezia-server"}, DeviceUser},
		{config.Connection{Type: "link"}, DeviceAccount},
		{config.Connection{Type: "mihomo"}, DeviceAccount},
		{config.Connection{Type: TypeSubscription}, DeviceAccount},
		{config.Connection{Type: config.TypeChain}, DeviceNone},
		{config.Connection{Type: "upstream"}, DeviceNone},
		{config.Connection{Type: "interface"}, DeviceNone},
	} {
		if got := DeviceKind(&tc.c); got != tc.want {
			t.Errorf("%s %v: got %q, want %q", tc.c.Type, tc.c.Params, got, tc.want)
		}
	}
}

// Every registered type is in the table on purpose: a new type has to say
// whether it takes a place in a device limit.
func TestDeviceKindCoversAllTypes(t *testing.T) {
	known := map[string]bool{"hyperv": true, "openconnect": true, "openvpn": true, "wireguard": true,
		"amnezia-server": true, "link": true, "mihomo": true, TypeSubscription: true, config.TypeChain: true, "upstream": true, "interface": true}
	for _, p := range All() {
		if !known[p.Type()] {
			t.Errorf("type %q: add it to DeviceKind and to deviceKind() in the web UI", p.Type())
		}
	}
}
