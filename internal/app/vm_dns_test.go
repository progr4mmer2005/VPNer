package app

import (
	"testing"

	"vpner/internal/config"
)

// The DNS server of a VM is added once, becomes the default only instead of
// the system DNS, and never replaces a server the user set up.
func TestWithVMDNS(t *testing.T) {
	d := config.DefaultDNS()
	changed, def := withVMDNS(&d, "c1", "INCY")
	if !changed || !def {
		t.Fatalf("changed %v, default %v; want both", changed, def)
	}
	s := d.Server(vmDNSID("c1"))
	if s == nil || s.Via != "c1" || s.Address != vmDoH {
		t.Fatalf("server %+v", s)
	}
	if len(d.Default) != 1 || d.Default[0] != vmDNSID("c1") {
		t.Errorf("default %v", d.Default)
	}
	if d.Server(config.DNSSystemID) == nil {
		t.Error("the system DNS must stay, to be chosen again")
	}
	// once is enough
	if changed, _ := withVMDNS(&d, "c1", "INCY"); changed {
		t.Error("added twice")
	}

	// the user already reaches a DNS server through the VM: left alone
	u := config.DefaultDNS()
	u.Servers = append(u.Servers, config.DNSServer{ID: "dns-mine", Name: "mine", Address: "1.1.1.1", Via: "c2"})
	if changed, _ := withVMDNS(&u, "c2", "INCY"); changed {
		t.Error("a server of the user's was duplicated")
	}

	// the user chose another default: the server is added, the default kept
	o := config.DefaultDNS()
	o.Servers = append(o.Servers, config.DNSServer{ID: "dns-q9", Name: "Quad9", Address: "9.9.9.9"})
	o.Default = []string{"dns-q9"}
	changed, def = withVMDNS(&o, "c3", "INCY")
	if !changed || def {
		t.Errorf("changed %v, default %v; want added, not default", changed, def)
	}
	if len(o.Default) != 1 || o.Default[0] != "dns-q9" {
		t.Errorf("the user's default changed: %v", o.Default)
	}
}
