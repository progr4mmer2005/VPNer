package engine

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
	"vpner/internal/providers"
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

const testWG = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
`

// A WireGuard connection with an endpoint runs in the tunnel process: the
// routing engine reaches it over SOCKS5 and holds no WireGuard device.
func TestTunnelSplit(t *testing.T) {
	cfg := testConfig()
	cfg.Connections = append(cfg.Connections, config.Connection{ID: "cwg", Name: "WG", Type: "wireguard", Enabled: true,
		Params: map[string]string{}, Secrets: map[string]string{"config": testWG}})
	cfg.Rules = append(cfg.Rules, config.Rule{Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"example.org"}, Target: "cwg"})
	ep := LocalEndpoint{Port: 30002, User: "u", Pass: "p"}
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", NoIPv6: true,
		Endpoints: map[string]LocalEndpoint{"cwork": {Port: 30001, User: "u", Pass: "p"}, "cwg": ep}})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range m["proxies"].([]map[string]any) {
		switch p["name"] {
		case "cwg":
			if p["type"] != "socks5" || p["port"] != 30002 {
				t.Errorf("tunnel connection must be reached over SOCKS5: %v", p)
			}
		case proxyDirect:
			if p["ip-version"] != "ipv4" {
				t.Errorf("without IPv6 direct must be IPv4 only: %v", p)
			}
		}
	}
	wg, _ := providers.Get("wireguard")
	out, err := wg.(providers.NativeProvider).Outbound(cfg.Conn("cwg"))
	if err != nil {
		t.Fatal(err)
	}
	if !IsTunnelOutbound(out) {
		t.Fatal("wireguard must go to the tunnel process")
	}
	tc := GenerateTunnels(TunnelInput{Outbounds: map[string]map[string]any{"cwg": out},
		Ports: map[string]int{"cwg": 30002}, User: "u", Pass: "p", ControllerPort: 9091, Secret: "s"})
	ls := tc["listeners"].([]map[string]any)
	if len(ls) != 1 || ls[0]["port"] != 30002 || ls[0]["proxy"] != "cwg" {
		t.Errorf("listeners = %v", ls)
	}
	if _, ok := tc["tun"]; ok {
		t.Error("the tunnel process must not open a TUN")
	}
	if bin := os.Getenv("VPNER_MIHOMO"); bin != "" {
		for _, c := range []map[string]any{m, tc} {
			if err := (&Mihomo{Bin: bin, WorkDir: t.TempDir()}).Test(c); err != nil {
				t.Fatal(err)
			}
		}
	}
}
