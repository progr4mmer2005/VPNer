package providers

import (
	"testing"

	"vpner/internal/config"
)

// A VM with a program VPNer sets up needs a device name that is a valid
// computer name: the program reports it to its service.
func TestVMDeviceName(t *testing.T) {
	vm := func(params map[string]string) (*VMSpec, error) {
		return hypervProvider{}.VM(&config.Connection{ID: "cvm", Name: "VM", Type: "hyperv", Params: params})
	}
	if _, err := vm(map[string]string{"app": VMAppIncy}); err == nil {
		t.Error("a device name is required with a program")
	}
	for _, bad := range []string{"Мой ПК", "-home", "home-", "a b", "x_y"} {
		if _, err := vm(map[string]string{"app": VMAppIncy, "deviceName": bad}); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
	s, err := vm(map[string]string{"app": VMAppIncy, "deviceName": "Incy-Home", "desktop": "false"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Hostname != "Incy-Home" || s.App != VMAppIncy || !s.Desktop {
		t.Errorf("spec = %+v", s)
	}
	// Without a program the name stays optional.
	if s, err := vm(map[string]string{}); err != nil || s.Hostname != "" {
		t.Errorf("plain VM: %+v %v", s, err)
	}
	if _, err := vm(map[string]string{"app": "other", "deviceName": "x"}); err == nil {
		t.Error("unknown program must be refused")
	}
}
