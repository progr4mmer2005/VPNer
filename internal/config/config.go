// Package config holds the persistent VPNer configuration: connections,
// routing rules and settings. Secrets are encrypted at rest (DPAPI on Windows).
package config

import (
	"vpner/internal/i18n"

	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// CurrentVersion 2: routing is no longer switched on automatically at launch
// unless the user enables that setting.
const CurrentVersion = 2

// Special rule targets.
const (
	TargetDirect = "DIRECT"
	TargetBlock  = "BLOCK"
)

type Config struct {
	Version     int          `json:"version"`
	Connections []Connection `json:"connections"`
	Rules       []Rule       `json:"rules"`
	Settings    Settings     `json:"settings"`
	DNS         DNS          `json:"dns"`
	// Appearance is the UI look (theme, colors, fonts, user variables). Only
	// the interface reads it, so it is kept as opaque JSON.
	Appearance json.RawMessage `json:"appearance,omitempty"`
	// PresetID and PresetName name the active preset: the connections,
	// rules, DNS and settings above. Empty until the user makes a second one.
	PresetID   string `json:"presetId,omitempty"`
	PresetName string `json:"presetName,omitempty"`
	// Presets are the other saved setups, not running.
	Presets []Preset `json:"presets,omitempty"`
}

// Preset is a whole VPNer setup kept under a name: connections, rules, DNS
// and routing settings. The look of the window and the settings of the
// program itself (language, autostart, window port) are not part of it.
type Preset struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Connections []Connection `json:"connections"`
	Rules       []Rule       `json:"rules"`
	Settings    Settings     `json:"settings"`
	DNS         DNS          `json:"dns"`
}

// KeepAppSettings puts the settings of the program itself from cur into s:
// they stay when another preset is applied.
func KeepAppSettings(s *Settings, cur Settings) {
	s.Language, s.Autostart, s.UIPort, s.StartOnLaunch = cur.Language, cur.Autostart, cur.UIPort, cur.StartOnLaunch
	s.DirectDNS = nil
}

// Connection is one VPN/proxy/gateway. Params are type specific and described
// by the provider's field list, which keeps the model open for new types.
type Connection struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Enabled   bool              `json:"enabled"`
	Autostart bool              `json:"autostart"`
	Params    map[string]string `json:"params"`
	// Secrets hold passwords/keys. On disk they are stored encrypted.
	Secrets map[string]string `json:"secrets,omitempty"`
}

// TypeChain is a connection made of other connections: traffic goes into
// the first one, through it into the second and so on, and leaves the
// internet through the last. Its hops are kept in Params["hops"].
const TypeChain = "chain"

// Hops lists the connection ids of a chain, first hop first.
func (c *Connection) Hops() []string {
	var out []string
	for _, h := range strings.Split(c.P("hops"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// SetHops stores the hops of a chain.
func (c *Connection) SetHops(ids []string) {
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	c.Params["hops"] = strings.Join(ids, ",")
}

func (c *Connection) P(key string) string {
	if c.Params == nil {
		return ""
	}
	return strings.TrimSpace(c.Params[key])
}

func (c *Connection) Bool(key string) bool {
	v := strings.ToLower(c.P(key))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func (c *Connection) S(key string) string {
	if c.Secrets == nil {
		return ""
	}
	return c.Secrets[key]
}

// Rule kinds.
const (
	RuleProcess       = "process"        // executable name: chrome.exe
	RuleProcessPath   = "process-path"   // full path, wildcards allowed
	RuleDomain        = "domain"         // exact domain
	RuleDomainSuffix  = "domain-suffix"  // domain and all subdomains
	RuleDomainKeyword = "domain-keyword" // substring
	RuleDomainRegex   = "domain-regex"
	RuleIPCIDR        = "ip-cidr"
	RuleGeoSite       = "geosite"
	RuleGeoIP         = "geoip"
	RuleDstPort       = "dst-port"
	RuleNetwork       = "network" // tcp|udp
)

type Rule struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Name    string   `json:"name,omitempty"`
	Kind    string   `json:"kind"`
	Values  []string `json:"values"`
	Target  string   `json:"target"` // connection id | DIRECT | BLOCK
	// Resolve allows IP rules to resolve domain names via DIRECT DNS to match.
	// Off by default: resolving would reveal the domain to the direct DNS
	// server even when the traffic finally goes into a VPN.
	Resolve bool `json:"resolve,omitempty"`
}

type Settings struct {
	// FinalTarget handles traffic that matched no rule.
	FinalTarget string `json:"finalTarget"`
	// DirectDNS is the pre-DNS-section list of servers; migrated into DNS on load.
	DirectDNS []string `json:"directDns,omitempty"`
	// KillSwitch blocks all outbound traffic via Windows Firewall while VPNer
	// is active, except through its own tunnel, so a crash cannot leak.
	KillSwitch bool `json:"killSwitch"`
	// AllowLAN lets local network traffic (192.168/16 etc.) go direct.
	AllowLAN bool `json:"allowLan"`
	// BlockQUIC drops UDP/443 so browsers fall back to TCP (more reliable
	// through some tunnels).
	BlockQUIC bool `json:"blockQuic"`
	// TunStack: mixed|system|gvisor.
	TunStack string `json:"tunStack"`
	// StartOnLaunch starts routing when the app starts (off by default: the
	// program does nothing until the user presses "Включить").
	StartOnLaunch bool `json:"startOnLaunch"`
	// Language of the interface ("" = like Windows).
	Language string `json:"language,omitempty"`
	// Autostart launches VPNer at Windows logon (scheduled task, elevated).
	Autostart bool `json:"autostart"`
	// UIPort for the local web UI (0 = random).
	UIPort int `json:"uiPort"`
	// SystemProxyOnly runs without TUN (only apps using the per-connection
	// local proxies are routed). For debugging/compatibility.
	NoTun bool `json:"noTun"`
	// LogLevel for the routing engine: info|warning|error|debug.
	LogLevel string `json:"logLevel"`
}

func Default() *Config {
	return &Config{
		Version: CurrentVersion,
		Rules:   []Rule{},
		DNS:     DefaultDNS(),
		Settings: Settings{
			FinalTarget:   TargetDirect,
			KillSwitch:    false,
			AllowLAN:      true,
			TunStack:      "mixed",
			StartOnLaunch: false,
			LogLevel:      "info",
		},
	}
}

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

func NewID(prefix string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// Validate checks structural consistency (provider-specific checks happen in
// the providers package).
func (c *Config) Validate() error {
	ids := map[string]bool{}
	for _, cn := range c.Connections {
		if !idRe.MatchString(cn.ID) {
			return fmt.Errorf(i18n.T("config.invalidConnectionId"), cn.ID)
		}
		if ids[cn.ID] {
			return fmt.Errorf(i18n.T("config.duplicateConnectionId"), cn.ID)
		}
		if strings.TrimSpace(cn.Name) == "" {
			return fmt.Errorf(i18n.T("config.connectionHasNoName"), cn.ID)
		}
		ids[cn.ID] = true
	}
	if err := c.validateChains(); err != nil {
		return err
	}
	check := func(t, where string) error {
		if t == TargetDirect || t == TargetBlock || ids[t] {
			return nil
		}
		return fmt.Errorf(i18n.T("config.unknownTarget"), where, t)
	}
	for _, r := range c.Rules {
		if err := check(r.Target, fmt.Sprintf(i18n.T("config.rule"), ruleTitle(r))); err != nil {
			return err
		}
	}
	if err := check(c.Settings.FinalTarget, i18n.T("config.defaultRule")); err != nil {
		return err
	}
	return c.DNS.validate(ids)
}

// validateChains checks that chains consist of existing connections that
// are not chains themselves. A chain that is on needs at least two hops.
func (c *Config) validateChains() error {
	for _, cn := range c.Connections {
		if cn.Type != TypeChain {
			continue
		}
		hops := cn.Hops()
		if cn.Enabled && len(hops) < 2 {
			return fmt.Errorf(i18n.T("config.chainNeedsTwoHops"), cn.Name)
		}
		seen := map[string]bool{}
		for _, h := range hops {
			hc := c.Conn(h)
			if hc == nil {
				return fmt.Errorf(i18n.T("config.chainHopNotFound"), cn.Name)
			}
			if hc.Type == TypeChain {
				return fmt.Errorf(i18n.T("config.chainHopIsChain"), cn.Name)
			}
			if seen[h] {
				return fmt.Errorf(i18n.T("config.chainHopRepeats"), cn.Name, hc.Name)
			}
			seen[h] = true
		}
	}
	return nil
}

func ruleTitle(r Rule) string {
	if r.Name != "" {
		return r.Name
	}
	return r.Kind + " " + strings.Join(r.Values, ",")
}

func (c *Config) Conn(id string) *Connection {
	for i := range c.Connections {
		if c.Connections[i].ID == id {
			return &c.Connections[i]
		}
	}
	return nil
}

// Clone returns a deep copy.
func (c *Config) Clone() *Config {
	b, _ := json.Marshal(c)
	var out Config
	json.Unmarshal(b, &out)
	return &out
}

// ---- storage ----

type Store struct {
	Path string
	mu   sync.Mutex
}

func (s *Store) Load() (*Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", s.Path, err)
	}
	for i := range cfg.Connections {
		for k, v := range cfg.Connections[i].Secrets {
			dec, err := unprotect(v)
			if err != nil {
				return nil, fmt.Errorf(i18n.T("config.couldNotDecryptSecret"), cfg.Connections[i].Name, k, err)
			}
			cfg.Connections[i].Secrets[k] = dec
		}
		if cfg.Connections[i].Params == nil {
			cfg.Connections[i].Params = map[string]string{}
		}
	}
	for p := range cfg.Presets {
		for i := range cfg.Presets[p].Connections {
			c := &cfg.Presets[p].Connections[i]
			for k, v := range c.Secrets {
				dec, err := unprotect(v)
				if err != nil {
					return nil, fmt.Errorf(i18n.T("config.couldNotDecryptSecret"), c.Name, k, err)
				}
				c.Secrets[k] = dec
			}
			if c.Params == nil {
				c.Params = map[string]string{}
			}
		}
		if cfg.Presets[p].Rules == nil {
			cfg.Presets[p].Rules = []Rule{}
		}
	}
	if cfg.Rules == nil {
		cfg.Rules = []Rule{}
	}
	migrateDNS(cfg)
	if cfg.Version < 2 {
		cfg.Settings.StartOnLaunch = false // was on by default before
		cfg.Version = 2
	}
	return cfg, nil
}

func (s *Store) Save(cfg *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := cfg.Clone()
	out.Version = CurrentVersion
	conns := []*Connection{}
	for i := range out.Connections {
		conns = append(conns, &out.Connections[i])
	}
	for p := range out.Presets {
		for i := range out.Presets[p].Connections {
			conns = append(conns, &out.Presets[p].Connections[i])
		}
	}
	for _, c := range conns {
		for k, v := range c.Secrets {
			if v == "" {
				delete(c.Secrets, k)
				continue
			}
			enc, err := protect(v)
			if err != nil {
				return err
			}
			c.Secrets[k] = enc
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// migrateDNS fills the DNS section for configs written before it existed.
func migrateDNS(cfg *Config) {
	if cfg.DNS.Mode == "" {
		cfg.DNS.Mode = DNSModeFakeIP
	}
	if cfg.DNS.Rules == nil {
		cfg.DNS.Rules = []DNSRule{}
	}
	if len(cfg.DNS.Servers) > 0 {
		cfg.Settings.DirectDNS = nil
		return
	}
	d := DefaultDNS()
	var def []string
	for i, a := range cfg.Settings.DirectDNS {
		a = strings.TrimSpace(a)
		if a == "" || a == "system" {
			continue
		}
		if _, err := DNSProtocol(a, false); err != nil {
			continue
		}
		id := fmt.Sprintf("dns-m%d", i)
		d.Servers = append(d.Servers, DNSServer{ID: id, Name: a, Address: a})
		def = append(def, id)
	}
	if len(def) > 0 {
		d.Default = def
	}
	cfg.DNS = d
	cfg.Settings.DirectDNS = nil
}
