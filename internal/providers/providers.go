// Package providers implements connection types as plug-ins. Each type
// describes its form fields (the UI renders them generically) and knows how to
// turn a configured connection into something the core can run:
//
//   - native: an outbound handled directly by the routing engine (mihomo)
//   - wsl:    a VPN daemon run in an isolated network namespace in WSL
//   - vm:     a gateway inside a dedicated Hyper-V virtual machine
//
// Adding a new VPN type means adding one file that calls Register.
package providers

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"vpner/internal/bridge"
	"vpner/internal/config"
)

type Runtime string

const (
	RuntimeNative Runtime = "native"
	RuntimeWSL    Runtime = "wsl"
	RuntimeVM     Runtime = "vm"
)

type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type Field struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Kind        string   `json:"kind"` // text|textarea|select|bool|number|interface|file
	Secret      bool     `json:"secret,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Help        string   `json:"help,omitempty"`
	Placeholder string   `json:"placeholder,omitempty"`
	Default     string   `json:"default,omitempty"`
	Options     []Option `json:"options,omitempty"`
	Advanced    bool     `json:"advanced,omitempty"`
}

type Provider interface {
	Type() string
	Title() string
	Description() string
	Runtime() Runtime
	Fields() []Field
}

// NativeProvider produces a mihomo proxy definition (without "name").
type NativeProvider interface {
	Provider
	Outbound(c *config.Connection) (map[string]any, error)
}

// WSLProvider produces a daemon spec for the WSL agent.
type WSLProvider interface {
	Provider
	Packages() []string
	Spec(c *config.Connection) (*bridge.ProcSpec, error)
}

// Importer recognises pasted text or a dropped file and builds a connection.
type Importer interface {
	Detect(filename string, data string) bool
	Import(filename string, data string) (*config.Connection, error)
}

var registry = map[string]Provider{}
var order []string

func Register(p Provider) {
	if _, dup := registry[p.Type()]; dup {
		panic("duplicate provider " + p.Type())
	}
	registry[p.Type()] = p
	order = append(order, p.Type())
}

func Get(t string) (Provider, error) {
	p, ok := registry[t]
	if !ok {
		return nil, fmt.Errorf("неизвестный тип подключения %q", t)
	}
	return p, nil
}

// displayOrder puts the most common types first in the UI.
var displayOrder = []string{"wireguard", "openconnect", "openvpn", "link", "hyperv", "upstream", "interface", "mihomo"}

func All() []Provider {
	rank := func(t string) int {
		for i, x := range displayOrder {
			if x == t {
				return i
			}
		}
		return len(displayOrder)
	}
	out := make([]Provider, 0, len(order))
	for _, t := range order {
		out = append(out, registry[t])
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Type()) < rank(out[j].Type()) })
	return out
}

// AllPackages lists Alpine packages needed by all WSL providers.
func AllPackages() []string {
	seen := map[string]bool{"iproute2": true}
	out := []string{"iproute2"}
	for _, p := range All() {
		if w, ok := p.(WSLProvider); ok {
			for _, pkg := range w.Packages() {
				if !seen[pkg] {
					seen[pkg] = true
					out = append(out, pkg)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// Validate checks required fields and lets the provider build its output.
func Validate(c *config.Connection) error {
	p, err := Get(c.Type)
	if err != nil {
		return err
	}
	for _, f := range p.Fields() {
		if !f.Required {
			continue
		}
		v := c.P(f.Key)
		if f.Secret {
			v = c.S(f.Key)
		}
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s: поле «%s» обязательно", c.Name, f.Label)
		}
	}
	switch pp := p.(type) {
	case NativeProvider:
		_, err = pp.Outbound(c)
	case WSLProvider:
		_, err = pp.Spec(c)
	case VMProvider:
		_, err = pp.VM(c)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	return nil
}

// Import auto-detects the type of pasted content.
func Import(filename, data string) (*config.Connection, error) {
	data = strings.TrimSpace(strings.TrimPrefix(data, "\uFEFF"))
	if data == "" {
		return nil, errors.New("пусто")
	}
	for _, t := range order {
		if im, ok := registry[t].(Importer); ok && im.Detect(filename, data) {
			c, err := im.Import(filename, data)
			if err != nil {
				return nil, err
			}
			c.Type = t
			if c.Params == nil {
				c.Params = map[string]string{}
			}
			if c.Secrets == nil {
				c.Secrets = map[string]string{}
			}
			c.Enabled = true
			return c, nil
		}
	}
	return nil, errors.New("не удалось распознать формат: поддерживаются .conf WireGuard/AmneziaWG, vpn:// (Amnezia), .ovpn, ссылки vless/vmess/trojan/ss/hysteria2/tuic/socks/http")
}

// ServerHosts returns hostnames/IPs of VPN servers a connection talks to, so
// the router can keep that traffic out of loops.
func ServerHosts(c *config.Connection) []string {
	if p, ok := registry[c.Type].(interface {
		ServerHosts(*config.Connection) []string
	}); ok {
		return p.ServerHosts(c)
	}
	return nil
}

// common fields
func fieldRouteAll() Field {
	return Field{Key: "routeAll", Label: "Весь трафик в туннель", Kind: "bool", Default: "true",
		Help: "Если сервер даёт только корпоративные подсети (split-tunnel), всё равно направлять туда весь трафик этого подключения. Выключите для корпоративных VPN, которые не выпускают в интернет."}
}

func fieldFallbackDNS() Field {
	return Field{Key: "fallbackDns", Label: "DNS, если VPN не выдал свой", Kind: "text", Default: "1.1.1.1 8.8.8.8",
		Help: "Запросы к этим серверам идут только внутри туннеля.", Advanced: true}
}

func fieldReconnect() Field {
	return Field{Key: "reconnect", Label: "Переподключаться автоматически", Kind: "bool", Default: "true", Advanced: true}
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' || r == '\t' || r == '\r' })
}

func boolDefault(c *config.Connection, key string, def bool) bool {
	if strings.TrimSpace(c.P(key)) == "" {
		return def
	}
	return c.Bool(key)
}

// VMProvider describes a gateway virtual machine (see internal/hyperv).
type VMProvider interface {
	Provider
	VM(c *config.Connection) (*VMSpec, error)
}

type VMSpec struct {
	VMName   string `json:"vmName"`
	MemoryMB int    `json:"memoryMb"`
	CPUs     int    `json:"cpus"`
	DiskGB   int    `json:"diskGb"`
	Desktop  bool   `json:"desktop"`
	WANMode  string `json:"wanMode"` // external|nat
	DNS      []string
}
