// Package engine drives mihomo, the routing core: it generates its config
// from VPNer's connections and rules, runs the process and talks to its API.
package engine

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"vpner/internal/config"
	"vpner/internal/providers"
)

// LocalEndpoint is a SOCKS5 server run by vpner.exe that leads into a WSL
// namespace or VM gateway.
type LocalEndpoint struct {
	Server string // default 127.0.0.1
	Port   int
	User   string
	Pass   string
	Iface  string // interface to reach it (default: loopback)
}

type GenInput struct {
	Cfg            *config.Config
	Endpoints      map[string]LocalEndpoint // connection id -> local SOCKS5 (WSL / VM)
	Running        map[string]bool          // connections that should accept traffic
	ControllerPort int
	Secret         string
	LoopbackIface  string
	TestPorts      map[string]int // connection id -> plain mixed listener bound to that connection
	SelfProcesses  []string       // our own executables: always DIRECT (VPN daemons' server traffic)
	// NoIPv6: the computer has no IPv6 connectivity, so direct connections
	// use IPv4 only instead of waiting for IPv6 attempts to time out.
	NoIPv6 bool
}

const (
	// proxyDirect is our own direct outbound: like DIRECT, but it prefers
	// IPv4 so that networks without IPv6 do not wait for IPv6 attempts.
	proxyDirect = "direct-out"
	proxyReject = "REJECT"
)

var lanCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32"}

// Some services break with fake IPs (NTP, connectivity checks, STUN, consoles).
var defaultFakeIPFilter = []string{
	"*.lan", "*.local", "*.localdomain", "*.home.arpa", "localhost.*",
	"+.msftconnecttest.com", "+.msftncsi.com", "time.windows.com", "time.*.com", "+.ntp.org", "+.pool.ntp.org",
	"+.stun.*.*", "+.stun.*.*.*", "stun.*", "+.xboxlive.com", "xbox.*.microsoft.com",
	"+.srv.nintendo.net", "+.stun.playstation.net", "lens.l.google.com",
}

// Generate builds the mihomo configuration.
func Generate(in GenInput) (map[string]any, error) {
	cfg := in.Cfg
	s := cfg.Settings

	directIP := "ipv4-prefer"
	if in.NoIPv6 {
		directIP = "ipv4"
	}
	proxies := []map[string]any{
		{"name": proxyDirect, "type": "direct", "udp": true, "ip-version": directIP},
	}
	known := map[string]bool{}
	var serverHosts []string
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		if !c.Enabled {
			continue
		}
		p, err := providers.Get(c.Type)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		switch pp := p.(type) {
		case providers.NativeProvider:
			out, err = pp.Outbound(c)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.Name, err)
			}
		default:
			ep, ok := in.Endpoints[c.ID]
			if !ok {
				continue // not running: rules targeting it are rejected below
			}
			server := ep.Server
			if server == "" {
				server = "127.0.0.1"
			}
			out = map[string]any{"type": "socks5", "server": server, "port": ep.Port,
				"username": ep.User, "password": ep.Pass, "udp": true}
			if ep.Iface != "" {
				out["interface-name"] = ep.Iface
			} else if in.LoopbackIface != "" {
				// mihomo binds outbound UDP sockets to the physical interface in
				// TUN mode, which breaks UDP to loopback; pin it to loopback.
				out["interface-name"] = in.LoopbackIface
			}
		}
		out["name"] = c.ID
		proxies = append(proxies, out)
		known[c.ID] = true
		serverHosts = append(serverHosts, providers.ServerHosts(c)...)
	}

	target := func(t string) string {
		switch t {
		case config.TargetDirect:
			return proxyDirect
		case config.TargetBlock, "":
			return proxyReject
		}
		if known[t] {
			return t
		}
		// Target disabled/missing: fail closed, never fall back to direct.
		return proxyReject
	}

	var rules []string
	for _, p := range in.SelfProcesses {
		rules = append(rules, "PROCESS-NAME,"+p+","+proxyDirect)
	}
	if s.BlockQUIC {
		rules = append(rules, "AND,((NETWORK,UDP),(DST-PORT,443)),"+proxyReject)
	}
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		lines, err := ruleLines(r, target(r.Target))
		if err != nil {
			return nil, err
		}
		rules = append(rules, lines...)
	}
	if s.AllowLAN {
		for _, cidr := range lanCIDRs {
			rules = append(rules, "IP-CIDR,"+cidr+","+proxyDirect+",no-resolve")
		}
	}
	rules = append(rules, "MATCH,"+target(s.FinalTarget))

	dnsSection := buildDNS(cfg.DNS)
	fakeFilter := append([]string{}, defaultFakeIPFilter...)
	for _, h := range uniq(serverHosts) {
		if net.ParseIP(h) == nil && h != "" {
			fakeFilter = append(fakeFilter, h)
		}
	}

	logLevel := s.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	stack := s.TunStack
	if stack == "" {
		stack = "mixed"
	}

	listeners := []map[string]any{}
	ids := make([]string, 0, len(in.TestPorts))
	for id := range in.TestPorts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !known[id] {
			continue
		}
		listeners = append(listeners, map[string]any{
			"name": "via-" + id, "type": "mixed", "listen": "127.0.0.1", "port": in.TestPorts[id], "proxy": id, "udp": true,
		})
	}

	m := map[string]any{
		"mode":                "rule",
		"log-level":           logLevel,
		"ipv6":                true, // IPv6 goes into the TUN too and obeys rules
		"allow-lan":           false,
		"bind-address":        "127.0.0.1",
		"find-process-mode":   "always",
		"unified-delay":       true,
		"tcp-concurrent":      true,
		"external-controller": fmt.Sprintf("127.0.0.1:%d", in.ControllerPort),
		"secret":              in.Secret,
		"geodata-mode":        true,
		"geo-auto-update":     true,
		"geo-update-interval": 72,
		"profile":             map[string]any{"store-selected": false, "store-fake-ip": true},
		"dns":       dnsSection,
		"proxies":   proxies,
		"listeners": listeners,
		"rules":     rules,
	}
	dnsSection["fake-ip-filter"] = fakeFilter
	if !s.NoTun {
		m["tun"] = map[string]any{
			"enable":                true,
			"device":                "VPNer",
			"stack":                 stack,
			"auto-route":            true,
			"auto-detect-interface": true,
			"strict-route":          true,
			"dns-hijack":            []string{"any:53", "tcp://any:53"},
		}
	}
	return m, nil
}

// ruleLines converts a VPNer rule into mihomo rule lines.
func ruleLines(r config.Rule, tgt string) ([]string, error) {
	var out []string
	for _, raw := range r.Values {
		v := strings.TrimSpace(raw)
		if v == "" || strings.HasPrefix(v, "#") {
			continue
		}
		var line string
		switch r.Kind {
		case config.RuleProcess:
			v = strings.Trim(v, `"`)
			line = "PROCESS-NAME-REGEX," + escapeRule("(?i)^"+globToRegex(v)+"$") + "," + tgt
		case config.RuleProcessPath:
			v = strings.ReplaceAll(strings.Trim(v, `"`), "/", `\`)
			line = "PROCESS-PATH-REGEX," + escapeRule("(?i)^"+globToRegex(v)+"$") + "," + tgt
		case config.RuleDomain, config.RuleDomainSuffix:
			d := normalizeDomain(v)
			if d == "" {
				continue
			}
			kind := "DOMAIN"
			if r.Kind == config.RuleDomainSuffix || strings.HasPrefix(v, "*.") || strings.HasPrefix(v, ".") {
				kind = "DOMAIN-SUFFIX"
			}
			line = kind + "," + d + "," + tgt
		case config.RuleDomainKeyword:
			line = "DOMAIN-KEYWORD," + escapeRule(strings.ToLower(v)) + "," + tgt
		case config.RuleDomainRegex:
			if _, err := regexp.Compile(v); err != nil {
				return nil, fmt.Errorf("неверное регулярное выражение %q: %v", v, err)
			}
			line = "DOMAIN-REGEX," + escapeRule(v) + "," + tgt
		case config.RuleIPCIDR:
			cidr := v
			if !strings.Contains(cidr, "/") {
				if ip := net.ParseIP(cidr); ip != nil && ip.To4() != nil {
					cidr += "/32"
				} else {
					cidr += "/128"
				}
			}
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				return nil, fmt.Errorf("неверная подсеть %q", v)
			}
			kind := "IP-CIDR"
			if ip.To4() == nil {
				kind = "IP-CIDR6"
			}
			line = kind + "," + cidr + "," + tgt
			if !r.Resolve {
				line += ",no-resolve"
			}
		case config.RuleGeoSite:
			line = "GEOSITE," + strings.ToLower(v) + "," + tgt
		case config.RuleGeoIP:
			line = "GEOIP," + strings.ToUpper(v) + "," + tgt
			if !r.Resolve {
				line += ",no-resolve"
			}
		case config.RuleDstPort:
			line = "DST-PORT," + v + "," + tgt
		case config.RuleNetwork:
			line = "NETWORK," + strings.ToUpper(v) + "," + tgt
		default:
			return nil, fmt.Errorf("неизвестный тип правила %q", r.Kind)
		}
		out = append(out, line)
	}
	return out, nil
}

func normalizeDomain(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	if i := strings.IndexAny(v, "/:?#"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimPrefix(v, "*.")
	v = strings.Trim(v, ".")
	return v
}

func globToRegex(g string) string {
	var b strings.Builder
	for _, r := range g {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

// escapeRule makes a value safe inside a comma-separated rule line.
func escapeRule(v string) string { return strings.ReplaceAll(v, ",", `\x2c`) }

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// dnsAddr renders a server for mihomo: "#<proxy>" sends the queries through
// that connection, "h3=true" forces DNS-over-HTTP/3.
func dnsAddr(sv config.DNSServer) string {
	var params []string
	if sv.Via != "" {
		params = append(params, sv.Via)
	}
	if sv.HTTP3 && strings.HasPrefix(sv.Address, "https://") {
		params = append(params, "h3=true")
	}
	if len(params) == 0 {
		return sv.Address
	}
	return sv.Address + "#" + strings.Join(params, "&")
}

func buildDNS(d config.DNS) map[string]any {
	addrs := func(ids []string) []string {
		var out []string
		for _, id := range ids {
			if sv := d.Server(id); sv != nil {
				out = append(out, dnsAddr(*sv))
			}
		}
		return out
	}
	nameservers := addrs(d.Default)
	if len(nameservers) == 0 {
		nameservers = []string{"system"}
	}
	// VPN server names are resolved without going through any VPN (that
	// would be circular): plain default servers, else the system resolver.
	var proxyNS []string
	for _, id := range d.Default {
		if sv := d.Server(id); sv != nil && sv.Via == "" {
			proxyNS = append(proxyNS, dnsAddr(*sv))
		}
	}
	if len(proxyNS) == 0 {
		proxyNS = []string{"system"}
	}
	policy := map[string]any{}
	for _, r := range d.Rules {
		if !r.Enabled {
			continue
		}
		sv := d.Server(r.Server)
		if sv == nil {
			continue
		}
		for _, v := range r.Values {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" || strings.HasPrefix(v, "#") {
				continue
			}
			var key string
			switch r.Kind {
			case "geosite":
				key = "geosite:" + v
			case "domain":
				key = normalizeDomain(v)
			default:
				key = "+." + normalizeDomain(v)
			}
			if _, dup := policy[key]; !dup && key != "+." && key != "" {
				policy[key] = []string{dnsAddr(*sv)}
			}
		}
	}
	mode := "fake-ip"
	if d.Mode == config.DNSModeRealIP {
		mode = "redir-host"
	}
	m := map[string]any{
		"enable":                  true,
		"ipv6":                    false,
		"enhanced-mode":           mode,
		"fake-ip-range":           "198.18.0.1/16",
		"use-system-hosts":        true,
		"default-nameserver":      []string{"system"},
		"nameserver":              nameservers,
		"proxy-server-nameserver": proxyNS,
	}
	if len(policy) > 0 {
		m["nameserver-policy"] = policy
	}
	return m
}
