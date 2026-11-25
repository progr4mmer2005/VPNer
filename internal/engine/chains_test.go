package engine

import (
	"strings"
	"testing"

	"vpner/internal/config"
	"vpner/internal/providers"
)

func chainConfig(hops ...string) *config.Config {
	cfg := testConfig()
	cfg.Connections = append(cfg.Connections,
		config.Connection{ID: "cwg", Name: "WG", Type: "wireguard", Enabled: true,
			Params: map[string]string{}, Secrets: map[string]string{"config": testWG}},
		config.Connection{ID: "cch", Name: "Chain", Type: config.TypeChain, Enabled: true,
			Params: map[string]string{"hops": strings.Join(hops, ",")}},
	)
	cfg.Rules = append(cfg.Rules, config.Rule{Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"example.org"}, Target: "cch"})
	return cfg
}

func proxyByName(m map[string]any, name string) map[string]any {
	for _, p := range m["proxies"].([]map[string]any) {
		if p["name"] == name {
			return p
		}
	}
	return nil
}

func hasRule(m map[string]any, line string) bool {
	for _, r := range m["rules"].([]string) {
		if r == line {
			return true
		}
	}
	return false
}

var testEPs = map[string]LocalEndpoint{"cwork": {Port: 30001, User: "u", Pass: "p"}, "cwg": {Port: 30002, User: "u", Pass: "p"}}

// A built-in hop after the first is a copy that dials through the previous
// hop; the connection itself stays as it is.
func TestChainBuiltInHop(t *testing.T) {
	cfg := chainConfig("cwg", "cnl")
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := providers.ValidateChains(cfg); err != nil {
		t.Fatal(err)
	}
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: testEPs})
	if err != nil {
		t.Fatal(err)
	}
	ch := proxyByName(m, "cch")
	if ch == nil || ch["type"] != "trojan" || ch["dialer-proxy"] != "cwg" {
		t.Fatalf("chain outbound = %v", ch)
	}
	if nl := proxyByName(m, "cnl"); nl == nil || nl["dialer-proxy"] != nil {
		t.Errorf("the connection itself must stay direct: %v", nl)
	}
	if !hasRule(m, "DOMAIN-SUFFIX,example.org,cch") {
		t.Error("rule must go to the chain")
	}
}

// A WireGuard hop after the first runs in the tunnel process and reaches
// its server through the routing engine's listener for the previous hop.
func TestChainTunnelHop(t *testing.T) {
	cfg := chainConfig("cnl", "cwg")
	cfg.Conn("cwg").Enabled = false // its own use is off; the chain copy still runs
	outs, prev := ChainTunnels(cfg)
	if outs["cch"] == nil || outs["cch"]["type"] != "wireguard" || prev["cch"] != "cnl" {
		t.Fatalf("tunnel copies = %v, prev = %v", outs, prev)
	}

	// Before the tunnel copy is up the chain is left out: its rules block.
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: testEPs,
		TestPorts: map[string]int{"cnl": 40001}})
	if err != nil {
		t.Fatal(err)
	}
	if proxyByName(m, "cch") != nil || !hasRule(m, "DOMAIN-SUFFIX,example.org,REJECT") {
		t.Error("a chain that is not up must block")
	}

	eps := map[string]LocalEndpoint{"cch": {Port: 30003, User: "u", Pass: "p"}}
	for k, v := range testEPs {
		eps[k] = v
	}
	m, err = Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: eps,
		TestPorts: map[string]int{"cnl": 40001}})
	if err != nil {
		t.Fatal(err)
	}
	if ch := proxyByName(m, "cch"); ch == nil || ch["type"] != "socks5" || ch["port"] != 30003 {
		t.Fatalf("chain must be reached over SOCKS5: %v", ch)
	}
	if proxyByName(m, "cwg") != nil {
		t.Error("a connection that is off must not be in the engine")
	}
	var via bool
	for _, l := range m["listeners"].([]map[string]any) {
		if l["proxy"] == "cnl" && l["port"] == 40001 {
			via = true
		}
	}
	if !via {
		t.Error("no listener for the previous hop")
	}

	tc := GenerateTunnels(TunnelInput{Outbounds: outs, Ports: map[string]int{"cch": 30003},
		Upstreams: map[string]int{"cch": 40001}, User: "u", Pass: "p", ControllerPort: 9091, Secret: "s"})
	if wg := proxyByName(tc, "cch"); wg == nil || wg["dialer-proxy"] != "up-cch" {
		t.Fatalf("tunnel copy = %v", wg)
	}
	if up := proxyByName(tc, "up-cch"); up == nil || up["type"] != "socks5" || up["port"] != 40001 {
		t.Errorf("upstream = %v", up)
	}
}

// Three hops: a WSL container first, then two built-in copies.
func TestChainThreeHops(t *testing.T) {
	cfg := chainConfig("cwork", "cnl", "cwg")
	if err := providers.ValidateChains(cfg); err != nil {
		t.Fatal(err)
	}
	chs := Chains(cfg)
	if len(chs) != 1 || len(chs[0].Steps) != 2 {
		t.Fatalf("chains = %+v", chs)
	}
	st := chs[0].Steps
	if st[0].Name != "cch.1" || st[0].Prev != "cwork" || st[0].Tunnel ||
		st[1].Name != "cch" || st[1].Prev != "cch.1" || !st[1].Tunnel {
		t.Errorf("steps = %+v", st)
	}
	eps := map[string]LocalEndpoint{"cch": {Port: 30003}}
	for k, v := range testEPs {
		eps[k] = v
	}
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: eps,
		TestPorts: map[string]int{"cch.1": 40002}})
	if err != nil {
		t.Fatal(err)
	}
	if p := proxyByName(m, "cch.1"); p == nil || p["dialer-proxy"] != "cwork" {
		t.Errorf("middle hop = %v", p)
	}
	var via bool
	for _, l := range m["listeners"].([]map[string]any) {
		if l["proxy"] == "cch.1" {
			via = true
		}
	}
	if !via {
		t.Error("no listener for the middle hop")
	}
}

// The first hop has to be on and running, or the chain blocks.
func TestChainFirstHopOff(t *testing.T) {
	cfg := chainConfig("cwg", "cnl")
	cfg.Conn("cwg").Enabled = false
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: testEPs})
	if err != nil {
		t.Fatal(err)
	}
	if proxyByName(m, "cch") != nil || !hasRule(m, "DOMAIN-SUFFIX,example.org,REJECT") {
		t.Error("chain with its first hop off must block")
	}
	// A WSL first hop that is not connected has no endpoint.
	cfg = chainConfig("cwork", "cnl")
	m, err = Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s"})
	if err != nil {
		t.Fatal(err)
	}
	if proxyByName(m, "cch") != nil {
		t.Error("chain through a container that is not connected must block")
	}
}

func TestChainValidation(t *testing.T) {
	cases := map[string]func(*config.Config){
		"one hop":      func(c *config.Config) { c.Conn("cch").SetHops([]string{"cnl"}) },
		"missing hop":  func(c *config.Config) { c.Conn("cch").SetHops([]string{"cnl", "nope"}) },
		"repeated hop": func(c *config.Config) { c.Conn("cch").SetHops([]string{"cnl", "cwg", "cnl"}) },
		"chain in chain": func(c *config.Config) {
			c.Connections = append(c.Connections, config.Connection{ID: "cch2", Name: "C2", Type: config.TypeChain,
				Params: map[string]string{"hops": "cch,cnl"}})
		},
	}
	for name, mod := range cases {
		cfg := chainConfig("cnl", "cwg")
		mod(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// A chain that is off may be unfinished.
	cfg := chainConfig("cnl")
	cfg.Conn("cch").Enabled = false
	if err := cfg.Validate(); err != nil {
		t.Errorf("chain that is off: %v", err)
	}
	// Only built-in protocols can follow the first hop.
	cfg = chainConfig("cnl", "cwork")
	if err := providers.ValidateChains(cfg); err == nil {
		t.Error("a WSL container after the first hop must be refused")
	}
}
