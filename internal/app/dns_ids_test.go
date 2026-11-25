package app

import (
	"strings"
	"testing"

	"vpner/internal/config"
)

// A server added in the UI and ticked as default (or used by a rule) before
// the first save must keep those references after it gets its real ID.
func TestAssignDNSIDsRemapsNewServers(t *testing.T) {
	d := config.DNS{
		Servers: []config.DNSServer{
			{ID: config.DNSSystemID, Name: "System", Address: "system"},
			{ID: "new-a1", Name: "Cloudflare", Address: " https://1.1.1.1/dns-query "},
			{ID: "new-b2", Name: "Quad9", Address: "tls://9.9.9.9"},
			{ID: "", Name: "Old UI", Address: "8.8.8.8"},
		},
		Default: []string{"new-a1", config.DNSSystemID},
		Rules:   []config.DNSRule{{Enabled: true, Kind: "domain-suffix", Values: []string{"x.org"}, Server: "new-b2"}},
		Mode:    config.DNSModeFakeIP,
	}
	assignDNSIDs(&d)
	cf, q9 := d.Servers[1].ID, d.Servers[2].ID
	for _, s := range d.Servers {
		if s.ID == "" || strings.HasPrefix(s.ID, "new-") {
			t.Fatalf("server %q kept a temporary ID %q", s.Name, s.ID)
		}
	}
	if d.Servers[0].ID != config.DNSSystemID {
		t.Errorf("existing ID changed: %q", d.Servers[0].ID)
	}
	if d.Servers[1].Address != "https://1.1.1.1/dns-query" {
		t.Errorf("address not trimmed: %q", d.Servers[1].Address)
	}
	if d.Default[0] != cf || d.Default[1] != config.DNSSystemID {
		t.Errorf("default not remapped: %v (cloudflare %s)", d.Default, cf)
	}
	if d.Rules[0].Server != q9 || d.Rules[0].ID == "" {
		t.Errorf("rule not remapped: %+v (quad9 %s)", d.Rules[0], q9)
	}
	if cf == q9 {
		t.Error("two new servers got one ID")
	}
}
