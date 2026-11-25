package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"vpner/internal/amnezia"
	"vpner/internal/config"
	"vpner/internal/i18n"
)

// XRay access shared from the AmneziaVPN app comes in two forms (its Share
// page, PageShare.qml): a "vpn://" key for the AmneziaVPN app, where the
// container "amnezia-xray" holds the client config in xray.last_config, and
// "XRay native format", the client config itself as JSON. AmneziaVPN gives
// no vless:// link. VPNer turns both into a share link and keeps that.

// amneziaXRayKey finds the XRay client config in a "vpn://" key: when the
// key is for XRay (its default container) or has no WireGuard/AmneziaWG.
func amneziaXRayKey(root map[string]any) (map[string]any, bool) {
	conts, _ := root["containers"].([]any)
	def, _ := root["defaultContainer"].(string)
	var xray map[string]any
	xrayDefault, hasWG := false, false
	for _, ci := range conts {
		cm, _ := ci.(map[string]any)
		if cm == nil {
			continue
		}
		if cm["awg"] != nil || cm["wireguard"] != nil {
			hasWG = true
		}
		pm, _ := cm["xray"].(map[string]any)
		if pm == nil {
			continue
		}
		if cfg := xrayLastConfig(pm["last_config"]); cfg != nil && xray == nil {
			xray = cfg
			name, _ := cm["container"].(string)
			xrayDefault = name == def
		}
	}
	if xray == nil || (hasWG && !xrayDefault) {
		return nil, false
	}
	return xray, true
}

// xrayLastConfig reads last_config: the client config as a JSON string, or
// an object with it under "config" (as AmneziaWG keeps its template).
func xrayLastConfig(v any) map[string]any {
	s, _ := v.(string)
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	if _, ok := m["outbounds"]; ok {
		return m
	}
	if inner, ok := m["config"].(string); ok {
		var c map[string]any
		if json.Unmarshal([]byte(inner), &c) == nil {
			if _, ok := c["outbounds"]; ok {
				return c
			}
		}
	}
	return nil
}

// xrayJSON reads pasted text as an XRay client config ("XRay native format").
func xrayJSON(data string) map[string]any {
	data = strings.TrimSpace(data)
	if !strings.HasPrefix(data, "{") || !strings.Contains(data, "outbounds") {
		return nil
	}
	var m map[string]any
	if json.Unmarshal([]byte(data), &m) != nil {
		return nil
	}
	if _, err := xrayConfigLink(m, ""); err != nil {
		return nil
	}
	return m
}

// amneziaXRayLink turns a "vpn://" XRay key into a share link.
func amneziaXRayLink(key string) (link string, ok bool, err error) {
	if !strings.HasPrefix(strings.TrimSpace(key), "vpn://") {
		return "", false, nil
	}
	root, err := amneziaKeyRoot(key)
	if err != nil {
		return "", false, nil // not ours: the WireGuard importer explains
	}
	cfg, ok := amneziaXRayKey(root)
	if !ok {
		return "", false, nil
	}
	desc, _ := root["description"].(string)
	if desc == "" {
		desc, _ = root["hostName"].(string)
	}
	link, err = xrayConfigLink(cfg, desc)
	return link, true, err
}

// xrayConfigLink makes a share link of the first VLESS (or Shadowsocks)
// outbound of an XRay client config.
func xrayConfigLink(cfg map[string]any, name string) (string, error) {
	outs, _ := cfg["outbounds"].([]any)
	for _, o := range outs {
		om, _ := o.(map[string]any)
		switch om["protocol"] {
		case "vless":
			return vlessLink(om, name)
		case "shadowsocks":
			return ssLink(om, name)
		}
	}
	return "", errors.New(i18n.T("providers.xrayNoVless"))
}

func jstr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	}
	return ""
}

func jmap(m map[string]any, k string) map[string]any {
	v, _ := m[k].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

func jfirst(m map[string]any, k string) map[string]any {
	a, _ := m[k].([]any)
	if len(a) == 0 {
		return map[string]any{}
	}
	v, _ := a[0].(map[string]any)
	if v == nil {
		return map[string]any{}
	}
	return v
}

func vlessLink(o map[string]any, name string) (string, error) {
	srv := jfirst(jmap(o, "settings"), "vnext")
	user := jfirst(srv, "users")
	host, port, id := jstr(srv, "address"), jstr(srv, "port"), jstr(user, "id")
	if port == "" {
		port = "443"
	}
	if host == "" || id == "" {
		return "", errors.New(i18n.T("providers.xrayNoVless"))
	}
	ss := jmap(o, "streamSettings")
	q := url.Values{}
	netw := jstr(ss, "network")
	if netw == "" || netw == "raw" {
		netw = "tcp"
	}
	q.Set("type", netw)
	q.Set("encryption", "none")
	if f := jstr(user, "flow"); f != "" {
		q.Set("flow", f)
	}
	switch sec := jstr(ss, "security"); sec {
	case "reality":
		r := jmap(ss, "realitySettings")
		q.Set("security", "reality")
		q.Set("sni", jstr(r, "serverName"))
		q.Set("pbk", jstr(r, "publicKey"))
		if v := jstr(r, "shortId"); v != "" {
			q.Set("sid", v)
		}
		if v := jstr(r, "fingerprint"); v != "" {
			q.Set("fp", v)
		}
		if v := jstr(r, "spiderX"); v != "" {
			q.Set("spx", v)
		}
	case "tls":
		t := jmap(ss, "tlsSettings")
		q.Set("security", "tls")
		if v := jstr(t, "serverName"); v != "" {
			q.Set("sni", v)
		}
		if v := jstr(t, "fingerprint"); v != "" {
			q.Set("fp", v)
		}
	}
	if netw == "grpc" {
		if v := jstr(jmap(ss, "grpcSettings"), "serviceName"); v != "" {
			q.Set("serviceName", v)
		}
	}
	if netw == "ws" {
		w := jmap(ss, "wsSettings")
		if v := jstr(w, "path"); v != "" {
			q.Set("path", v)
		}
		if v := jstr(jmap(w, "headers"), "Host"); v != "" {
			q.Set("host", v)
		}
	}
	u := url.URL{Scheme: "vless", User: url.User(id), Host: net.JoinHostPort(host, port), RawQuery: q.Encode(), Fragment: name}
	return u.String(), nil
}

func ssLink(o map[string]any, name string) (string, error) {
	s := jfirst(jmap(o, "settings"), "servers")
	host, port, method, pass := jstr(s, "address"), jstr(s, "port"), jstr(s, "method"), jstr(s, "password")
	if host == "" || port == "" || method == "" {
		return "", errors.New(i18n.T("providers.xrayNoVless"))
	}
	u := url.URL{Scheme: "ss", User: url.UserPassword(method, pass), Host: net.JoinHostPort(host, port), Fragment: name}
	return u.String(), nil
}

// NetInfo is what the chain editor needs to know about a hop: whether it
// runs over UDP (which VPN programs in a VM or a container often do not
// pass), and the name a REALITY hop shows in its TLS handshake. A VPN
// program that sends connections where the name they carry points
// (sniffing) takes a REALITY hop with a decoy name to the real site
// instead of the server; SelfName is a name that points to the server.
type NetInfo struct {
	UDP      bool   `json:"udp,omitempty"`
	Reality  bool   `json:"reality,omitempty"`
	SNI      string `json:"sni,omitempty"`
	SelfName string `json:"selfName,omitempty"`
	SNISelf  bool   `json:"sniSelf,omitempty"` // the name points to the server itself
}

// HopNet describes a connection for the chain editor (nil: nothing to say).
func HopNet(c *config.Connection) *NetInfo {
	switch c.Type {
	case "amnezia-server":
		return &NetInfo{UDP: true}
	case "wireguard":
		n := &NetInfo{UDP: true}
		if hosts := (wireguardProvider{}).ServerHosts(c); len(hosts) > 0 {
			n.SelfName = amnezia.SelfName(hosts[0])
		}
		return n
	case TypeSubscription:
		sel, ok := SubSelected(c)
		if !ok {
			return nil
		}
		n := HopNet(&config.Connection{Type: "link", Secrets: map[string]string{"link": sel.Link}})
		return n
	case "link":
		m, _, err := parseLink(strings.TrimSpace(c.S("link")))
		if err != nil {
			return nil
		}
		n := &NetInfo{}
		switch fmt.Sprint(m["type"]) {
		case "hysteria2", "tuic", "wireguard":
			n.UDP = true
		}
		if _, ok := m["reality-opts"]; ok {
			srv, _ := m["server"].(string)
			sni, _ := m["servername"].(string)
			n.Reality, n.SNI, n.SelfName = true, sni, amnezia.SelfName(srv)
			n.SNISelf = sni != "" && (strings.EqualFold(sni, srv) || strings.EqualFold(sni, n.SelfName) || pointsToIP(sni, srv))
		}
		if !n.UDP && !n.Reality {
			return nil
		}
		return n
	}
	return nil
}

// pointsToIP: names of services that resolve to the IP written in them
// (sslip.io, nip.io), so it is known without asking DNS.
func pointsToIP(name, ip string) bool {
	if net.ParseIP(ip) == nil {
		return false
	}
	low := strings.ToLower(name)
	for _, svc := range []string{".sslip.io", ".nip.io"} {
		if strings.HasSuffix(low, svc) {
			label := strings.TrimSuffix(low, svc)
			if strings.HasSuffix(label, ip) || strings.HasSuffix(label, strings.NewReplacer(".", "-", ":", "-").Replace(ip)) {
				return true
			}
		}
	}
	return false
}
