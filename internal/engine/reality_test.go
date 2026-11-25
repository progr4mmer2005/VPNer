package engine

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
)

const testReality = "vless://9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d@203.0.113.7:443?security=reality&sni=www.example.com&fp=chrome&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#XR"

// realityConfig: a REALITY link "cxr", a chain "cch" that ends in it, and a
// hand-written proxy "craw" that sets the key exchange itself.
func realityConfig() *config.Config {
	cfg := testConfig()
	cfg.Connections = append(cfg.Connections,
		config.Connection{ID: "cxr", Name: "XR", Type: "link", Enabled: true,
			Params: map[string]string{}, Secrets: map[string]string{"link": testReality}},
		config.Connection{ID: "cch", Name: "Chain", Type: config.TypeChain, Enabled: true,
			Params: map[string]string{"hops": "cwork,cxr"}},
		config.Connection{ID: "craw", Name: "Raw", Type: "mihomo", Enabled: true, Params: map[string]string{},
			Secrets: map[string]string{"yaml": "type: vless\nserver: 203.0.113.8\nport: 443\nuuid: 9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d\ntls: true\nservername: www.example.com\nclient-fingerprint: chrome\nreality-opts:\n  public-key: Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw\n  support-x25519mlkem768: false\n"}},
	)
	return cfg
}

func realityGen(t *testing.T, cfg *config.Config) map[string]any {
	t.Helper()
	m, err := Generate(GenInput{Cfg: cfg, ControllerPort: 9090, Secret: "s", Endpoints: testEPs,
		TestPorts: map[string]int{"cxr": 30010, "cch": 30011, RealityTwin("cxr"): 30012}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// pqHello reports whether an outbound offers X25519MLKEM768 in its hello.
func pqHello(t *testing.T, p map[string]any) bool {
	t.Helper()
	if p == nil {
		t.Fatal("outbound is missing")
	}
	ro, ok := p["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("no reality-opts in %v", p)
	}
	return ro["support-x25519mlkem768"] == true
}

// A REALITY outbound comes with a twin that sends the other hello, so that
// the monitor can find out which one the server answers. The twin reaches
// the server the same way (through the same hop in a chain) and takes no
// traffic: no rule, listener or DNS server can name it.
func TestRealityTwin(t *testing.T) {
	m := realityGen(t, realityConfig())
	if pqHello(t, proxyByName(m, "cxr")) || !pqHello(t, proxyByName(m, "alt-cxr")) {
		t.Fatal("a new connection sends the older hello and its twin the new one")
	}
	ch, tw := proxyByName(m, "cch"), proxyByName(m, "alt-cch")
	if pqHello(t, ch) || !pqHello(t, tw) {
		t.Fatal("the chain's last hop and its twin must differ the same way")
	}
	if ch["dialer-proxy"] != "cwork" || tw["dialer-proxy"] != "cwork" {
		t.Fatalf("both must go through the first hop: %v, %v", ch["dialer-proxy"], tw["dialer-proxy"])
	}
	if tw["server"] != ch["server"] || tw["uuid"] != ch["uuid"] {
		t.Fatal("the twin must be the same server and user")
	}
	if Outbounds(m)["alt-cxr"] || Outbounds(m)["alt-cch"] {
		t.Fatal("a twin is not a routing target")
	}
	for _, l := range m["listeners"].([]map[string]any) {
		if isRealityTwin(l["proxy"].(string)) {
			t.Fatalf("listener on a twin: %v", l)
		}
	}
	// Not REALITY, or the key exchange is set by hand: no twin.
	if proxyByName(m, "alt-cnl") != nil || proxyByName(m, "alt-craw") != nil {
		t.Fatal("twin for an outbound whose hello is not ours to choose")
	}
	if ro := proxyByName(m, "craw")["reality-opts"].(map[string]any); ro["support-x25519mlkem768"] != false {
		t.Fatalf("a hand-written setting must stay: %v", ro)
	}
}

// The hello that worked is remembered in the connection: it and every chain
// copy of it use it from the start, and the twins take the other one.
func TestRealityRemembered(t *testing.T) {
	cfg := realityConfig()
	cfg.Conn("cxr").Params[ParamRealityHello] = RealityHelloPQ
	m := realityGen(t, cfg)
	if !pqHello(t, proxyByName(m, "cxr")) || pqHello(t, proxyByName(m, "alt-cxr")) {
		t.Fatal("connection must send the remembered hello")
	}
	if !pqHello(t, proxyByName(m, "cch")) || pqHello(t, proxyByName(m, "alt-cch")) {
		t.Fatal("the chain copy must send the hello remembered for its connection")
	}
}

func TestRealityOwner(t *testing.T) {
	cfg := realityConfig()
	for id, want := range map[string]string{
		"cxr":   "cxr", // the connection itself
		"cch":   "cxr", // a chain: the connection of its last hop
		"cnl":   "",    // not REALITY
		"craw":  "",    // set by hand
		"cwork": "",    // not a built-in protocol
		"nope":  "",
	} {
		if got := RealityOwner(cfg, id); got != want {
			t.Errorf("RealityOwner(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestMihomoAcceptsReality runs the real engine in test mode over a config
// with twins when VPNER_MIHOMO points to mihomo.exe.
func TestMihomoAcceptsReality(t *testing.T) {
	bin := os.Getenv("VPNER_MIHOMO")
	if bin == "" {
		t.Skip("set VPNER_MIHOMO to mihomo.exe to run")
	}
	cfg := realityConfig()
	cfg.DNS.Rules = nil // no geosite rule: nothing to download for the test
	m := realityGen(t, cfg)
	mh := &Mihomo{Bin: bin, WorkDir: t.TempDir()}
	if err := mh.Test(m); err != nil {
		b, _ := yaml.Marshal(m["proxies"])
		t.Fatalf("%v\n%s", err, b)
	}
}
