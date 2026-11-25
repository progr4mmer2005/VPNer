package app

import (
	"testing"

	"vpner/internal/config"
	"vpner/internal/engine"
)

const awg = "cawg"

// rulesCfg is the user's setup in short: a work site directly, programs and
// sites through Amnezia, everything else directly.
func rulesCfg(gitlabOn bool) *config.Config {
	cfg := config.Default()
	cfg.Settings.FinalTarget = config.TargetDirect
	cfg.Rules = []config.Rule{
		{Enabled: gitlabOn, Kind: config.RuleDomainSuffix, Values: []string{"gitlab.hyundai.ru"}, Target: config.TargetDirect},
		{Enabled: true, Kind: config.RuleIPCIDR, Values: []string{"10.123.150.30"}, Target: "ccisco"},
		{Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"youtube.com"}, Target: awg},
		{Enabled: true, Kind: config.RuleProcess, Values: []string{"Claude.exe"}, Target: awg},
	}
	return cfg
}

func testRoutes(cfg *config.Config, outbounds ...string) *routes {
	known := map[string]bool{"direct-out": true}
	for _, o := range outbounds {
		known[o] = true
	}
	return &routes{cfg: cfg, known: known}
}

type connOpt func(*engine.Connection)

func liveConn(process, host, chain string, opts ...connOpt) engine.Connection {
	var c engine.Connection
	c.ID = "1"
	c.Chains = []string{chain}
	c.Rule = "Match"
	c.Metadata.Type = "Tun"
	c.Metadata.Network = "tcp"
	c.Metadata.Process = process
	c.Metadata.Host = host
	c.Metadata.DestPort = "443"
	for _, o := range opts {
		o(&c)
	}
	return c
}

func matched(rule, payload string) connOpt {
	return func(c *engine.Connection) { c.Rule, c.Payload = rule, payload }
}

var self = []string{"vpner.exe", "mihomo.exe"}

func TestStaleRoute(t *testing.T) {
	before := testRoutes(rulesCfg(false), awg, "ccisco")
	after := testRoutes(rulesCfg(true), awg, "ccisco")
	cases := []struct {
		name      string
		c         engine.Connection
		prev, cur *routes
		want      string // "" = keep
	}{
		// The case that started it: the browser inside Claude kept an
		// HTTP/2 connection to the work site through Amnezia after the site
		// was switched to go directly.
		{"rule turned on moves the site", liveConn("Claude.exe", "gitlab.hyundai.ru", awg), before, after, "direct-out"},
		{"rule turned off moves it back", liveConn("Claude.exe", "gitlab.hyundai.ru", "direct-out"), after, before, awg},
		{"bare IP is matched by the sniffed name", liveConn("Claude.exe", "", awg, func(c *engine.Connection) {
			c.Metadata.DestIP = "195.9.1.10"
			c.Metadata.SniffHost = "gitlab.hyundai.ru"
		}), before, after, "direct-out"},
		{"other sites of the program stay", liveConn("Claude.exe", "claude.ai", awg), before, after, ""},
		{"route unchanged by this change", liveConn("firefox.exe", "www.youtube.com", awg), before, after, ""},
		{"already on the new route", liveConn("Claude.exe", "gitlab.hyundai.ru", "direct-out"), before, after, ""},
		// The previous rules already sent it where the new ones do: the
		// connection is on another route for a reason VPNer cannot see, and
		// it must not be cut on every unrelated change.
		{"not moved by this change", liveConn("ssh.exe", "build.example", awg), after, after, ""},
		{"no previous routing known", liveConn("Claude.exe", "gitlab.hyundai.ru", awg), nil, after, "direct-out"},
		// Each of these would be moved by the rules (youtube.com goes
		// through Amnezia) if it were not VPNer's own.
		{"VPNer's own connections stay", liveConn("vpner.exe", "www.youtube.com", "direct-out"), nil, after, ""},
		{"the engine's own connections stay", liveConn("mihomo.exe", "www.youtube.com", "direct-out"), nil, after, ""},
		{"listener connections stay", liveConn("", "www.youtube.com", "direct-out", func(c *engine.Connection) {
			c.Metadata.Type = "Socks5"
		}), nil, after, ""},
		{"loopback stays", liveConn("Claude.exe", "", "direct-out", func(c *engine.Connection) {
			c.Metadata.DestIP = "127.0.0.1"
		}), nil, after, ""},
		{"no chain", liveConn("Claude.exe", "gitlab.hyundai.ru", "", func(c *engine.Connection) { c.Chains = nil }), before, after, ""},
	}
	for _, tc := range cases {
		got, ok := staleRoute(tc.c, self, tc.prev, tc.cur)
		if (tc.want != "") != ok || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, ok, tc.want)
		}
	}
}

// A VPN that stops (or is disabled) takes its outbound out of the config:
// its rules fail closed, and connections still on it are closed.
func TestStaleRouteVPNGone(t *testing.T) {
	cfg := rulesCfg(true)
	up, down := testRoutes(cfg, awg, "ccisco"), testRoutes(cfg, "ccisco")
	if got, ok := staleRoute(liveConn("Claude.exe", "claude.ai", awg), self, up, down); !ok || got != "REJECT" {
		t.Errorf("got %q, %v; want REJECT", got, ok)
	}
	if _, ok := staleRoute(liveConn("firefox.exe", "example.com", "direct-out"), self, up, down); ok {
		t.Error("direct traffic must stay")
	}
}

// Rules only the engine can evaluate stop the decision: the connection is
// kept unless the engine itself matched that rule.
func TestStaleRouteEngineOnlyRules(t *testing.T) {
	geo := func(target string) *config.Config {
		cfg := rulesCfg(true)
		cfg.Rules = append([]config.Rule{{Enabled: true, Kind: config.RuleGeoSite, Values: []string{"youtube"}, Target: target}}, cfg.Rules...)
		return cfg
	}
	prev, cur := testRoutes(geo(awg), awg), testRoutes(geo(config.TargetDirect), awg)
	c := liveConn("firefox.exe", "www.youtube.com", awg, matched("GeoSite", "youtube"))
	if got, ok := staleRoute(c, self, prev, cur); !ok || got != "direct-out" {
		t.Errorf("matched site category: got %q, %v; want direct-out", got, ok)
	}
	c = liveConn("Claude.exe", "gitlab.hyundai.ru", awg)
	if got, ok := staleRoute(c, self, nil, cur); ok {
		t.Errorf("unknown site category must keep the connection, got %q", got)
	}
	// An IP rule that resolves the name cannot be decided either.
	cfg := rulesCfg(true)
	cfg.Rules = append([]config.Rule{{Enabled: true, Kind: config.RuleIPCIDR, Values: []string{"203.0.113.0/24"}, Target: awg, Resolve: true}}, cfg.Rules...)
	if got, ok := staleRoute(liveConn("Claude.exe", "gitlab.hyundai.ru", awg), self, nil, testRoutes(cfg, awg)); ok {
		t.Errorf("resolving IP rule must keep the connection, got %q", got)
	}
}

func TestStaleRoutePortsAndQUIC(t *testing.T) {
	cfg := rulesCfg(true)
	cfg.Rules = append([]config.Rule{{Enabled: true, Kind: config.RuleDstPort, Values: []string{"6881-6889"}, Target: config.TargetBlock}}, cfg.Rules...)
	torrent := liveConn("qbittorrent.exe", "", "direct-out", func(c *engine.Connection) {
		c.Metadata.DestIP = "203.0.113.7"
		c.Metadata.DestPort = "6885"
	})
	if got, ok := staleRoute(torrent, self, testRoutes(rulesCfg(true)), testRoutes(cfg)); !ok || got != "REJECT" {
		t.Errorf("port rule: got %q, %v; want REJECT", got, ok)
	}
	quic := cfg.Clone()
	quic.Settings.BlockQUIC = true
	c := liveConn("chrome.exe", "example.com", "direct-out", func(c *engine.Connection) { c.Metadata.Network = "udp" })
	if got, ok := staleRoute(c, self, testRoutes(cfg), testRoutes(quic)); !ok || got != "REJECT" {
		t.Errorf("QUIC block: got %q, %v; want REJECT", got, ok)
	}
}

// The route check in the interface uses the same evaluation and skips what
// only the engine knows, with a note for site categories.
func TestRouteCheckEvaluation(t *testing.T) {
	cfg := rulesCfg(true)
	cfg.Rules = append([]config.Rule{{Enabled: true, Kind: config.RuleGeoSite, Values: []string{"youtube"}, Target: awg}}, cfg.Rules...)
	h := route(cfg, routeQuery{host: "gitlab.hyundai.ru", process: "claude.exe"}, false)
	if !h.known || h.target != config.TargetDirect || len(h.notes) != 1 {
		t.Errorf("domain: %+v", h)
	}
	h = route(cfg, routeQuery{host: "claude.ai", process: "claude.exe"}, false)
	if h.target != awg {
		t.Errorf("program rule: %+v", h)
	}
	cfg.Settings.AllowLAN = true
	if h := route(cfg, routeQuery{ip: []byte{192, 168, 1, 1}}, false); h.target != config.TargetDirect {
		t.Errorf("LAN: %+v", h)
	}
	if h := route(cfg, routeQuery{ip: []byte{10, 123, 150, 30}}, false); h.target != "ccisco" {
		t.Errorf("IP rule comes before LAN: %+v", h)
	}
}
