package engine

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
)

func testConfig() *config.Config {
	cfg := config.Default()
	cfg.Connections = []config.Connection{
		{ID: "cnl", Name: "NL", Type: "link", Enabled: true, Params: map[string]string{},
			Secrets: map[string]string{"link": "trojan://pass@nl.example.com:443?sni=nl.example.com#NL"}},
		{ID: "cwork", Name: "Work", Type: "openconnect", Enabled: true, Params: map[string]string{"server": "vpn.corp"}},
	}
	cfg.Rules = []config.Rule{
		{Enabled: true, Kind: config.RuleProcess, Values: []string{"chrome.exe"}, Target: "cnl"},
		{Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"corp.example"}, Target: "cwork"},
	}
	cfg.DNS = config.DNS{
		Mode: config.DNSModeFakeIP,
		Servers: []config.DNSServer{
			{ID: "sys", Name: "system", Address: "system"},
			{ID: "cf", Name: "Cloudflare DoH", Address: "https://1.1.1.1/dns-query", HTTP3: true},
			{ID: "dot", Name: "Google DoT", Address: "tls://8.8.8.8"},
			{ID: "doq", Name: "AdGuard DoQ", Address: "quic://94.140.14.14"},
			{ID: "tcp", Name: "Quad9 TCP", Address: "tcp://9.9.9.9"},
			{ID: "udp", Name: "Yandex", Address: "77.88.8.8"},
			{ID: "vianl", Name: "DoH via NL", Address: "https://dns.google/dns-query", Via: "cnl"},
		},
		Default: []string{"cf", "vianl"},
		Rules: []config.DNSRule{
			{Enabled: true, Kind: "domain-suffix", Values: []string{"ru", "*.yandex.net"}, Server: "udp"},
			{Enabled: true, Kind: "geosite", Values: []string{"category-ads-all"}, Server: "doq"},
			{Enabled: true, Kind: "domain", Values: []string{"intranet.local"}, Server: "sys"},
		},
	}
	return cfg
}

func TestDNSGeneration(t *testing.T) {
	cfg := testConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	dns := m["dns"].(map[string]any)
	ns := strings.Join(dns["nameserver"].([]string), " ")
	if ns != "https://1.1.1.1/dns-query#h3=true https://dns.google/dns-query#cnl" {
		t.Errorf("nameserver = %q", ns)
	}
	if p := strings.Join(dns["proxy-server-nameserver"].([]string), " "); p != "https://1.1.1.1/dns-query#h3=true" {
		t.Errorf("proxy-server-nameserver must avoid VPN-routed servers: %q", p)
	}
	pol := dns["nameserver-policy"].(map[string]any)
	for key, want := range map[string]string{"+.ru": "77.88.8.8", "+.yandex.net": "77.88.8.8", "geosite:category-ads-all": "quic://94.140.14.14", "intranet.local": "system"} {
		got, ok := pol[key].([]string)
		if !ok || got[0] != want {
			t.Errorf("policy[%s] = %v, want %s", key, pol[key], want)
		}
	}
}

func TestDNSValidation(t *testing.T) {
	cfg := testConfig()
	cfg.DNS.Servers = append(cfg.DNS.Servers, config.DNSServer{ID: "bad", Name: "bad", Address: "dns.example.com"})
	if err := cfg.Validate(); err == nil {
		t.Error("plain DNS by hostname must be rejected")
	}
	cfg = testConfig()
	cfg.DNS.Servers[0].Via = "cnl" // system via VPN makes no sense
	if err := cfg.Validate(); err == nil {
		t.Error("system resolver through a VPN must be rejected")
	}
}

// TestMihomoAccepts runs the real engine in test mode when VPNER_MIHOMO
// points to mihomo.exe.
func TestMihomoAccepts(t *testing.T) {
	bin := os.Getenv("VPNER_MIHOMO")
	if bin == "" {
		t.Skip("set VPNER_MIHOMO to mihomo.exe to run")
	}
	m, err := Generate(GenInput{Cfg: testConfig(), ControllerPort: 9090, Secret: "s",
		Endpoints: map[string]LocalEndpoint{"cwork": {Port: 30001, User: "u", Pass: "p"}}})
	if err != nil {
		t.Fatal(err)
	}
	mh := &Mihomo{Bin: bin, WorkDir: t.TempDir()}
	if err := mh.Test(m); err != nil {
		b, _ := yaml.Marshal(m["dns"])
		t.Fatalf("%v\n%s", err, b)
	}
}
