package config

import (
	"errors"
	"vpner/internal/i18n"

	"fmt"
	"net"
	"net/url"
	"strings"
)

// DNS configures name resolution for traffic VPNer sends directly, like a
// YogaDNS-style resolver: named upstream servers (any protocol), each
// reachable directly or through a VPN connection, and per-domain rules.
// Traffic routed into a VPN is always resolved inside that VPN.
type DNS struct {
	Servers []DNSServer `json:"servers"`
	Rules   []DNSRule   `json:"rules"`
	// Default lists server ids used for everything not matched by a rule.
	Default []string `json:"default"`
	// Mode: fake-ip (recommended: names are resolved where the traffic
	// goes, nothing leaks) or real-ip (apps see real addresses).
	Mode string `json:"mode"`
}

type DNSServer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"` // system | 1.1.1.1 | tls://… | https://… | quic://… | tcp://…
	Via     string `json:"via"`     // "" = direct, otherwise a connection id
	HTTP3   bool   `json:"http3,omitempty"`
}

type DNSRule struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	Kind    string   `json:"kind"` // domain-suffix | domain | geosite
	Values  []string `json:"values"`
	Server  string   `json:"server"` // server id
}

const (
	DNSModeFakeIP = "fake-ip"
	DNSModeRealIP = "real-ip"
	DNSSystemID   = "dns-system"
)

// DefaultDNS returns the initial resolver setup: the system resolver.
func DefaultDNS() DNS {
	return DNS{
		Servers: []DNSServer{{ID: DNSSystemID, Name: i18n.T("config.systemYourNetworksDns"), Address: "system"}},
		Rules:   []DNSRule{},
		Default: []string{DNSSystemID},
		Mode:    DNSModeFakeIP,
	}
}

// DNSProtocol names the transport of an address for display and validation.
func DNSProtocol(addr string, h3 bool) (string, error) {
	a := strings.TrimSpace(addr)
	if a == "" {
		return "", errors.New(i18n.T("config.emptyDnsAddress"))
	}
	if a == "system" {
		return i18n.T("config.system"), nil
	}
	if !strings.Contains(a, "://") {
		host := a
		if h, _, err := net.SplitHostPort(a); err == nil {
			host = h
		}
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf(i18n.T("config.dnsPlainDnsServerNeeds"), a)
		}
		return "UDP", nil
	}
	u, err := url.Parse(a)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf(i18n.T("config.dnsInvalidAddress"), a)
	}
	switch u.Scheme {
	case "udp":
		return "UDP", nil
	case "tcp":
		return "TCP", nil
	case "tls":
		return "DoT", nil
	case "https":
		if h3 {
			return "DoH3", nil
		}
		return "DoH", nil
	case "quic":
		return "DoQ", nil
	case "dhcp":
		return "DHCP", nil
	}
	return "", fmt.Errorf(i18n.T("config.dnsProtocolIsNotSupported"), a, u.Scheme)
}

func (d *DNS) Server(id string) *DNSServer {
	for i := range d.Servers {
		if d.Servers[i].ID == id {
			return &d.Servers[i]
		}
	}
	return nil
}

func (d *DNS) validate(conns map[string]bool) error {
	ids := map[string]bool{}
	for _, s := range d.Servers {
		if s.ID == "" || ids[s.ID] {
			return fmt.Errorf(i18n.T("config.dnsServerInvalidOrDuplicate"), s.Name)
		}
		ids[s.ID] = true
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf(i18n.T("config.dnsServerHasNoName"), s.Address)
		}
		if _, err := DNSProtocol(s.Address, s.HTTP3); err != nil {
			return err
		}
		if s.Via != "" && !conns[s.Via] {
			return fmt.Errorf(i18n.T("config.dnsServerRoutesConnectionWas"), s.Name)
		}
		if s.Via != "" && s.Address == "system" {
			return fmt.Errorf(i18n.T("config.dnsServerSystemDnsCannot"), s.Name)
		}
	}
	if len(d.Default) == 0 {
		return errors.New(i18n.T("config.noDefaultDnsChosen"))
	}
	for _, id := range d.Default {
		if !ids[id] {
			return errors.New(i18n.T("config.defaultDnsRefersToDeleted"))
		}
	}
	for _, r := range d.Rules {
		if !ids[r.Server] {
			return fmt.Errorf(i18n.T("config.dnsRuleRefersToUnknown"), r.Values)
		}
		switch r.Kind {
		case "domain-suffix", "domain", "geosite":
		default:
			return fmt.Errorf(i18n.T("config.unknownDnsRuleType"), r.Kind)
		}
	}
	if d.Mode != DNSModeFakeIP && d.Mode != DNSModeRealIP {
		return fmt.Errorf(i18n.T("config.unknownDnsMode"), d.Mode)
	}
	return nil
}
