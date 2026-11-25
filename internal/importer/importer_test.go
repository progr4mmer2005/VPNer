package importer

import (
	"encoding/json"
	"strings"
	"testing"

	"vpner/internal/config"
	"vpner/internal/providers"
)

const links = `# мои серверы
vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@1.2.3.4:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#NL
trojan://pass@example.com:443?type=ws&path=%2Fws&host=example.com&sni=example.com#DE

ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@5.6.7.8:8388#NL
`

func TestLinkList(t *testing.T) {
	res, err := Parse("", links)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "list" || len(res.Connections) != 3 {
		t.Fatalf("kind=%s conns=%d", res.Kind, len(res.Connections))
	}
	if res.Connections[2].Name != "NL (2)" {
		t.Errorf("duplicate name not made unique: %q", res.Connections[2].Name)
	}
}

func TestBase64Subscription(t *testing.T) {
	body := "dmxlc3M6Ly85YjFkZWI0ZC0zYjdkLTRiYWQtOWJkZC0yYjBkN2IzZGNiNmRAMS4yLjMuNDo0NDM/c2VjdXJpdHk9dGxzJnNuaT1hLmNvbSNBCnRyb2phbjovL3Bhc3NAZXhhbXBsZS5jb206NDQzP3NuaT1leGFtcGxlLmNvbSNC"
	res, err := Parse("subscription", body)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "list" || len(res.Connections) != 2 {
		t.Fatalf("kind=%s conns=%d", res.Kind, len(res.Connections))
	}
}

const clash = `
mixed-port: 7890
proxies:
  - {name: "🇳🇱 NL", type: vless, server: 1.2.3.4, port: 443, uuid: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d, tls: true}
  - name: "🇩🇪 DE"
    type: trojan
    server: de.example.com
    port: 443
    password: x
proxy-groups:
  - {name: Auto, type: url-test, proxies: ["🇩🇪 DE", "🇳🇱 NL"]}
  - {name: Proxy, type: select, proxies: [Auto, DIRECT]}
rules:
  - DOMAIN-SUFFIX,youtube.com,Proxy
  - DOMAIN-SUFFIX,googlevideo.com,Proxy
  - DOMAIN,chat.openai.com,🇳🇱 NL
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - RULE-SET,ads,REJECT
  - GEOIP,RU,DIRECT
  - MATCH,Proxy
`

func TestClash(t *testing.T) {
	res, err := Parse("config.yaml", clash)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "clash" || len(res.Connections) != 2 {
		t.Fatalf("kind=%s conns=%d", res.Kind, len(res.Connections))
	}
	de := res.Connections[1].ID
	nl := res.Connections[0].ID
	if len(res.Rules) != 4 {
		t.Fatalf("rules=%d %+v", len(res.Rules), res.Rules)
	}
	if r := res.Rules[0]; r.Kind != config.RuleDomainSuffix || len(r.Values) != 2 || r.Target != de {
		t.Errorf("merged youtube rule wrong: %+v (want target DE via groups)", r)
	}
	if res.Rules[1].Target != nl {
		t.Errorf("direct proxy target wrong: %+v", res.Rules[1])
	}
	if r := res.Rules[2]; r.Target != config.TargetDirect || r.Resolve {
		t.Errorf("ip rule wrong: %+v", r)
	}
	if r := res.Rules[3]; r.Kind != config.RuleGeoIP || !r.Resolve {
		t.Errorf("geoip rule wrong: %+v", r)
	}
	if res.FinalTarget != de {
		t.Errorf("final target %q, want DE", res.FinalTarget)
	}
	if !strings.Contains(strings.Join(res.Notes, "|"), "RULE-SET ×1") {
		t.Errorf("skipped rule not reported: %v", res.Notes)
	}
}

func TestProfileRoundTrip(t *testing.T) {
	cfg := config.Default()
	cfg.Connections = []config.Connection{
		{ID: "cold1", Name: "Work", Type: "openconnect", Enabled: true, Params: map[string]string{"server": "vpn.corp"}, Secrets: map[string]string{"password": "secret"}},
		{ID: "cold2", Name: "VM", Type: "hyperv", Enabled: true, Params: map[string]string{"lanIp": "10.211.0.10", "wanMac": "00155D000001"}, Secrets: map[string]string{"gwPass": "x"}},
	}
	cfg.Rules = []config.Rule{{ID: "r1", Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"corp"}, Target: "cold1"}}
	cfg.Settings.FinalTarget = "cold2"
	for _, withSecrets := range []bool{true, false} {
		data, err := Export(cfg, withSecrets)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), `"gwPass"`) {
			t.Error("per-machine gateway password exported")
		}
		res, err := Parse("vpner-profile.json", string(data))
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != "profile" || len(res.Connections) != 2 {
			t.Fatalf("kind=%s conns=%d", res.Kind, len(res.Connections))
		}
		work, vm := res.Connections[0], res.Connections[1]
		if work.ID == "cold1" || res.Rules[0].Target != work.ID || res.FinalTarget != vm.ID {
			t.Errorf("ids not remapped: work=%s rule=%s final=%s", work.ID, res.Rules[0].Target, res.FinalTarget)
		}
		if vm.P("lanIp") != "" {
			t.Error("VM identity should not be imported")
		}
		if got := work.S("password"); (got == "secret") != withSecrets {
			t.Errorf("withSecrets=%v but password=%q", withSecrets, got)
		}
	}
}

// The look travels with the profile; per-connection colors follow the new
// connection ids.
func TestProfileAppearance(t *testing.T) {
	cfg := config.Default()
	cfg.Connections = []config.Connection{{ID: "cold1", Name: "Work", Type: "openconnect", Enabled: true, Params: map[string]string{"server": "vpn.corp"}}}
	cfg.Appearance = []byte(`{"theme":"cli","values":{"conn:cold1":{"m":"own","v":"#ff0000"}}}`)
	data, err := Export(cfg, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Parse("vpner-profile.json", string(data))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Theme  string         `json:"theme"`
		Values map[string]any `json:"values"`
	}
	if err := json.Unmarshal(res.Appearance, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Values["conn:"+res.Connections[0].ID]; got.Theme != "cli" || !ok || len(got.Values) != 1 {
		t.Errorf("appearance not carried over or not remapped: %s", res.Appearance)
	}
}

// A proxy with dialer-proxy becomes a chain, and its rules go to the chain.
func TestClashDialerProxy(t *testing.T) {
	const y = `proxies:
  - {name: Entry, type: trojan, server: a.example.com, port: 443, password: p}
  - {name: Exit, type: trojan, server: b.example.com, port: 443, password: p, dialer-proxy: Entry}
rules:
  - DOMAIN-SUFFIX,example.org,Exit
  - MATCH,DIRECT
`
	res, err := Parse("config.yaml", y)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Connections) != 3 {
		t.Fatalf("conns = %d", len(res.Connections))
	}
	entry, exit, ch := res.Connections[0], res.Connections[1], res.Connections[2]
	if strings.Contains(exit.S("yaml"), "dialer-proxy") {
		t.Errorf("copy of the proxy must not keep dialer-proxy: %s", exit.S("yaml"))
	}
	if ch.Type != config.TypeChain || strings.Join(ch.Hops(), ",") != entry.ID+","+exit.ID {
		t.Fatalf("chain = %+v", ch)
	}
	if res.Rules[0].Target != ch.ID {
		t.Errorf("rule must go to the chain: %+v", res.Rules[0])
	}
}

// Chains in a profile point at the new ids of their connections.
func TestProfileChain(t *testing.T) {
	p := Profile{VPNer: ProfileVersion, Connections: []config.Connection{
		{ID: "a", Name: "A", Type: "link", Enabled: true, Secrets: map[string]string{"link": "trojan://p@a.example.com:443#A"}},
		{ID: "b", Name: "B", Type: "link", Enabled: true, Secrets: map[string]string{"link": "trojan://p@b.example.com:443#B"}},
		{ID: "c", Name: "C", Type: config.TypeChain, Enabled: true, Params: map[string]string{"hops": "a,b"},
			Secrets: map[string]string{"hopConfig.b": "conf", "hopClient.b": "id", "hopConfig.gone": "x"}},
	}}
	b, _ := json.Marshal(p)
	res, err := Parse("profile.json", string(b))
	if err != nil {
		t.Fatal(err)
	}
	ids := res.Connections[0].ID + "," + res.Connections[1].ID
	if got := strings.Join(res.Connections[2].Hops(), ","); got != ids || !res.Connections[2].Enabled {
		t.Errorf("hops = %q, want %q", got, ids)
	}
	ch, b2 := res.Connections[2], res.Connections[1].ID
	if ch.S("hopConfig."+b2) != "conf" || ch.S("hopClient."+b2) != "id" || len(ch.Secrets) != 2 {
		t.Errorf("chain users must follow the new hop ids: %v", ch.Secrets)
	}
}

// A VM with a program VPNer sets up keeps its subscription link in a profile
// exported with secrets, but not the identity of the VM: imported, it is a
// new VM, so the program in it counts as a new device.
func TestProfileVMApp(t *testing.T) {
	cfg := config.Default()
	cfg.Connections = []config.Connection{{ID: "cvm", Name: "VM", Type: "hyperv", Enabled: true,
		Params:  map[string]string{"app": "incy", "lanIp": "10.77.0.10", "wanMac": "00155D000001", "lanMac": "00155D000002"},
		Secrets: map[string]string{"subscription": "https://sub.example.com/x", "gwPass": "secret"}}}
	for _, withSecrets := range []bool{true, false} {
		b, err := Export(cfg, withSecrets)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Parse("profile.json", string(b))
		if err != nil {
			t.Fatal(err)
		}
		if d := res.Summary().Devices; len(d) != 1 || d[0] != (Device{Name: "VM", Kind: providers.DeviceVMApp}) {
			t.Errorf("the import must warn about the new device: %v", d)
		}
		c := res.Connections[0]
		if c.P("app") != "incy" {
			t.Errorf("app lost: %v", c.Params)
		}
		if got := c.S("subscription"); (got != "") != withSecrets {
			t.Errorf("withSecrets=%v: subscription %q", withSecrets, got)
		}
		for _, k := range []string{"lanIp", "wanMac", "lanMac"} {
			if c.P(k) != "" {
				t.Errorf("%s must not move to another VM", k)
			}
		}
		if c.S("gwPass") != "" || c.ID == "cvm" {
			t.Error("the imported VM must be a new one")
		}
	}
}
