package providers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
)

// ---- share links: vless/vmess/trojan/ss/hysteria2/tuic/socks/http ----

type linkProvider struct{}

func init() { Register(linkProvider{}) }

func (linkProvider) Type() string { return "link" }
func (linkProvider) Title() string {
	return "Ссылка (VLESS/Reality, VMess, Trojan, Shadowsocks, Hysteria2, TUIC)"
}
func (linkProvider) Runtime() Runtime { return RuntimeNative }
func (linkProvider) Description() string {
	return "Ссылка-ключ вида vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, socks5://, http://. Работает прямо в движке."
}
func (linkProvider) Fields() []Field {
	return []Field{{Key: "link", Label: "Ссылка", Kind: "textarea", Secret: true, Required: true, Placeholder: "vless://uuid@host:443?security=reality&pbk=...&sni=...#name"}}
}

var linkSchemes = []string{"vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://", "socks5://", "socks://", "http://", "https://"}

func (linkProvider) Detect(_ string, data string) bool {
	low := strings.ToLower(strings.TrimSpace(data))
	for _, s := range linkSchemes {
		if strings.HasPrefix(low, s) {
			return !strings.ContainsAny(strings.TrimSpace(data), "\n")
		}
	}
	return false
}

func (p linkProvider) Import(_ string, data string) (*config.Connection, error) {
	link := strings.TrimSpace(data)
	m, name, err := parseLink(link)
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = fmt.Sprintf("%v %v", m["type"], m["server"])
	}
	return &config.Connection{Name: name, Secrets: map[string]string{"link": link}, Params: map[string]string{}}, nil
}

func (linkProvider) Outbound(c *config.Connection) (map[string]any, error) {
	m, _, err := parseLink(strings.TrimSpace(c.S("link")))
	return m, err
}

func (linkProvider) ServerHosts(c *config.Connection) []string {
	m, _, err := parseLink(strings.TrimSpace(c.S("link")))
	if err != nil {
		return nil
	}
	if s, ok := m["server"].(string); ok {
		return []string{s}
	}
	return nil
}

func b64any(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("неверный base64")
}

func portOf(u *url.URL, def int) (int, error) {
	if u.Port() == "" {
		return def, nil
	}
	return strconv.Atoi(u.Port())
}

func truthy(s string) bool {
	s = strings.ToLower(s)
	return s == "1" || s == "true" || s == "yes"
}

// transportOpts maps v2ray-style query params onto mihomo transport options.
func transportOpts(m map[string]any, q url.Values, network string) {
	if network == "" || network == "tcp" || network == "raw" {
		if q.Get("headerType") == "http" {
			m["network"] = "http"
			m["http-opts"] = map[string]any{"path": []string{orDefault(q.Get("path"), "/")}, "headers": map[string]any{"Host": splitList(q.Get("host"))}}
		}
		return
	}
	m["network"] = network
	switch network {
	case "ws", "httpupgrade":
		ws := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		if network == "httpupgrade" {
			m["network"] = "ws"
			ws["v2ray-http-upgrade"] = true
		}
		m["ws-opts"] = ws
	case "grpc":
		m["grpc-opts"] = map[string]any{"grpc-service-name": q.Get("serviceName")}
	case "h2", "http":
		m["network"] = "h2"
		h2 := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			h2["host"] = splitList(h)
		}
		m["h2-opts"] = h2
	case "xhttp", "splithttp":
		m["network"] = "xhttp"
		x := map[string]any{"path": orDefault(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			x["host"] = h
		}
		if mode := q.Get("mode"); mode != "" {
			x["mode"] = mode
		}
		m["xhttp-opts"] = x
	}
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func tlsOpts(m map[string]any, q url.Values, sniKey string) {
	if sni := orDefault(q.Get("sni"), q.Get("peer")); sni != "" {
		m[sniKey] = sni
	}
	if fp := q.Get("fp"); fp != "" {
		m["client-fingerprint"] = fp
	}
	if a := q.Get("alpn"); a != "" {
		m["alpn"] = splitList(a)
	}
	if truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) {
		m["skip-cert-verify"] = true
	}
}

func parseLink(link string) (map[string]any, string, error) {
	low := strings.ToLower(link)
	if strings.HasPrefix(low, "vmess://") {
		return parseVMess(link)
	}
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", fmt.Errorf("ссылка: %v", err)
	}
	name := u.Fragment
	q := u.Query()
	host := u.Hostname()
	if host == "" && u.Scheme != "ss" {
		return nil, "", errors.New("в ссылке нет адреса сервера")
	}
	m := map[string]any{"server": host, "udp": true}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		port, err := portOf(u, 443)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "vless"
		m["port"] = port
		m["uuid"] = u.User.Username()
		if f := q.Get("flow"); f != "" {
			m["flow"] = f
		}
		sec := q.Get("security")
		if sec == "tls" || sec == "reality" {
			m["tls"] = true
			tlsOpts(m, q, "servername")
		}
		if sec == "reality" {
			ro := map[string]any{"public-key": q.Get("pbk")}
			if sid := q.Get("sid"); sid != "" {
				ro["short-id"] = sid
			}
			m["reality-opts"] = ro
			if _, ok := m["client-fingerprint"]; !ok {
				m["client-fingerprint"] = "chrome"
			}
		}
		if enc := q.Get("encryption"); enc != "" && enc != "none" {
			m["encryption"] = enc
		}
		transportOpts(m, q, q.Get("type"))
	case "trojan":
		port, err := portOf(u, 443)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "trojan"
		m["port"] = port
		m["password"] = u.User.Username()
		tlsOpts(m, q, "sni")
		if q.Get("security") == "reality" {
			m["reality-opts"] = map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
		}
		transportOpts(m, q, q.Get("type"))
	case "ss":
		return parseSS(u)
	case "hysteria2", "hy2":
		port, err := portOf(u, 443)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "hysteria2"
		m["port"] = port
		pw := u.User.Username()
		if p, ok := u.User.Password(); ok {
			pw += ":" + p
		}
		m["password"] = pw
		tlsOpts(m, q, "sni")
		if o := q.Get("obfs"); o != "" {
			m["obfs"] = o
			m["obfs-password"] = q.Get("obfs-password")
		}
		if mp := q.Get("mport"); mp != "" {
			m["ports"] = mp
		}
		if pin := q.Get("pinSHA256"); pin != "" {
			m["fingerprint"] = pin
		}
	case "tuic":
		port, err := portOf(u, 443)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "tuic"
		m["port"] = port
		m["uuid"] = u.User.Username()
		pw, _ := u.User.Password()
		m["password"] = pw
		tlsOpts(m, q, "sni")
		if cc := q.Get("congestion_control"); cc != "" {
			m["congestion-controller"] = cc
		}
		if mode := q.Get("udp_relay_mode"); mode != "" {
			m["udp-relay-mode"] = mode
		}
		if _, ok := m["alpn"]; !ok {
			m["alpn"] = []string{"h3"}
		}
	case "socks5", "socks":
		port, err := portOf(u, 1080)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "socks5"
		m["port"] = port
		if u.User != nil {
			m["username"] = u.User.Username()
			p, _ := u.User.Password()
			m["password"] = p
		}
	case "http", "https":
		def := 80
		if u.Scheme == "https" {
			def = 443
			m["tls"] = true
		}
		port, err := portOf(u, def)
		if err != nil {
			return nil, "", err
		}
		m["type"] = "http"
		m["port"] = port
		delete(m, "udp")
		if u.User != nil {
			m["username"] = u.User.Username()
			p, _ := u.User.Password()
			m["password"] = p
		}
	default:
		return nil, "", fmt.Errorf("неподдерживаемая схема %q", u.Scheme)
	}
	return m, name, nil
}

func parseSS(u *url.URL) (map[string]any, string, error) {
	name := u.Fragment
	var method, password, host string
	var port int
	if u.User != nil && u.Hostname() != "" {
		// SIP002: ss://base64(method:password)@host:port or ss://method:password@host:port
		user := u.User.Username()
		if pw, ok := u.User.Password(); ok {
			method, password = user, pw
		} else if b, err := b64any(user); err == nil {
			method, password, _ = strings.Cut(string(b), ":")
		} else {
			return nil, "", errors.New("ss://: не удалось разобрать метод/пароль")
		}
		host = u.Hostname()
		p, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, "", errors.New("ss://: нет порта")
		}
		port = p
	} else {
		// legacy: ss://base64(method:password@host:port)
		b, err := b64any(u.Host + u.Path)
		if err != nil {
			return nil, "", errors.New("ss://: неверный base64")
		}
		s := string(b)
		at := strings.LastIndex(s, "@")
		if at < 0 {
			return nil, "", errors.New("ss://: неверный формат")
		}
		method, password, _ = strings.Cut(s[:at], ":")
		h, ps, err := net.SplitHostPort(s[at+1:])
		if err != nil {
			return nil, "", err
		}
		host = h
		port, _ = strconv.Atoi(ps)
	}
	m := map[string]any{"type": "ss", "server": host, "port": port, "cipher": method, "password": password, "udp": true}
	if pl := u.Query().Get("plugin"); pl != "" {
		parts := strings.Split(pl, ";")
		opts := map[string]any{}
		for _, kv := range parts[1:] {
			k, v, _ := strings.Cut(kv, "=")
			opts[k] = v
		}
		switch {
		case strings.Contains(parts[0], "obfs"):
			m["plugin"] = "obfs"
			m["plugin-opts"] = map[string]any{"mode": opts["obfs"], "host": opts["obfs-host"]}
		case strings.Contains(parts[0], "v2ray"):
			po := map[string]any{"mode": "websocket"}
			if v, ok := opts["host"]; ok {
				po["host"] = v
			}
			if v, ok := opts["path"]; ok {
				po["path"] = v
			}
			if _, ok := opts["tls"]; ok {
				po["tls"] = true
			}
			m["plugin"] = "v2ray-plugin"
			m["plugin-opts"] = po
		default:
			return nil, "", fmt.Errorf("ss://: плагин %q не поддерживается", parts[0])
		}
	}
	return m, name, nil
}

func parseVMess(link string) (map[string]any, string, error) {
	b, err := b64any(strings.TrimPrefix(strings.TrimPrefix(link, "vmess://"), "VMESS://"))
	if err != nil {
		return nil, "", errors.New("vmess://: неверный base64")
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, "", errors.New("vmess://: неверный JSON")
	}
	str := func(k string) string {
		switch x := v[k].(type) {
		case string:
			return x
		case float64:
			return strconv.Itoa(int(x))
		}
		return ""
	}
	port, err := strconv.Atoi(str("port"))
	if err != nil {
		return nil, "", errors.New("vmess://: неверный порт")
	}
	aid, _ := strconv.Atoi(str("aid"))
	m := map[string]any{"type": "vmess", "server": str("add"), "port": port, "uuid": str("id"), "alterId": aid,
		"cipher": orDefault(str("scy"), "auto"), "udp": true}
	q := url.Values{}
	q.Set("path", str("path"))
	q.Set("host", str("host"))
	q.Set("serviceName", str("path"))
	q.Set("headerType", str("type"))
	if str("tls") == "tls" {
		m["tls"] = true
		q.Set("sni", str("sni"))
		q.Set("fp", str("fp"))
		q.Set("alpn", str("alpn"))
		tlsOpts(m, q, "servername")
	}
	transportOpts(m, q, str("net"))
	return m, str("ps"), nil
}

// ---- raw mihomo proxy YAML (escape hatch for anything else) ----

type rawProvider struct{}

func init() { Register(rawProvider{}) }

func (rawProvider) Type() string     { return "mihomo" }
func (rawProvider) Title() string    { return "Прокси mihomo (YAML)" }
func (rawProvider) Runtime() Runtime { return RuntimeNative }
func (rawProvider) Description() string {
	return "Любой протокол, который понимает mihomo, описанный вручную в YAML (одна запись из раздела proxies). Для продвинутых."
}
func (rawProvider) Fields() []Field {
	return []Field{{Key: "yaml", Label: "YAML прокси", Kind: "textarea", Secret: true, Required: true,
		Placeholder: "type: vless\nserver: example.com\nport: 443\nuuid: ...\ntls: true"}}
}

func (rawProvider) Outbound(c *config.Connection) (map[string]any, error) {
	var m map[string]any
	if err := yaml.Unmarshal([]byte(c.S("yaml")), &m); err != nil {
		return nil, fmt.Errorf("YAML: %v", err)
	}
	if lst, ok := m["proxies"].([]any); ok && len(lst) > 0 {
		if mm, ok := lst[0].(map[string]any); ok {
			m = mm
		}
	}
	if _, ok := m["type"]; !ok {
		return nil, errors.New("в YAML нет поля type")
	}
	delete(m, "name")
	return m, nil
}

func (rawProvider) ServerHosts(c *config.Connection) []string {
	m, err := rawProvider{}.Outbound(c)
	if err != nil {
		return nil
	}
	if s, ok := m["server"].(string); ok {
		return []string{s}
	}
	return nil
}

// ---- upstream proxy: an existing SOCKS5/HTTP proxy (e.g. your own VM) ----

type upstreamProvider struct{}

func init() { Register(upstreamProvider{}) }

func (upstreamProvider) Type() string { return "upstream" }
func (upstreamProvider) Title() string {
	return "Внешний прокси / своя виртуалка"
}
func (upstreamProvider) Runtime() Runtime { return RuntimeNative }
func (upstreamProvider) Description() string {
	return "Уже работающий SOCKS5/HTTP-прокси: например, шлюз в вашей собственной виртуалке с VPN-программой или прокси-порт другой программы."
}
func (upstreamProvider) Fields() []Field {
	return []Field{
		{Key: "proto", Label: "Протокол", Kind: "select", Default: "socks5", Options: []Option{{"socks5", "SOCKS5"}, {"http", "HTTP"}}},
		{Key: "host", Label: "Адрес", Kind: "text", Required: true, Placeholder: "192.168.255.2"},
		{Key: "port", Label: "Порт", Kind: "number", Required: true, Placeholder: "1080"},
		{Key: "username", Label: "Логин", Kind: "text"},
		{Key: "password", Label: "Пароль", Kind: "text", Secret: true},
		{Key: "interface", Label: "Сетевой интерфейс до прокси", Kind: "interface", Advanced: true,
			Help: "Если прокси в виртуалке на внутреннем коммутаторе Hyper-V — выберите его vEthernet-адаптер."},
		{Key: "udp", Label: "Поддержка UDP", Kind: "bool", Default: "true", Advanced: true},
	}
}

func (upstreamProvider) Outbound(c *config.Connection) (map[string]any, error) {
	port, err := strconv.Atoi(c.P("port"))
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("неверный порт")
	}
	t := c.P("proto")
	if t == "" {
		t = "socks5"
	}
	m := map[string]any{"type": t, "server": c.P("host"), "port": port}
	if t == "socks5" {
		m["udp"] = boolDefault(c, "udp", true)
	}
	if u := c.P("username"); u != "" {
		m["username"] = u
		m["password"] = c.S("password")
	}
	if i := c.P("interface"); i != "" {
		m["interface-name"] = i
	}
	return m, nil
}

func (upstreamProvider) ServerHosts(c *config.Connection) []string { return []string{c.P("host")} }

// ---- network interface: send traffic out of a specific adapter ----

type ifaceProvider struct{}

func init() { Register(ifaceProvider{}) }

func (ifaceProvider) Type() string     { return "interface" }
func (ifaceProvider) Title() string    { return "Сетевой интерфейс" }
func (ifaceProvider) Runtime() Runtime { return RuntimeNative }
func (ifaceProvider) Description() string {
	return "Выпускать трафик через конкретный адаптер Windows: второй провайдер, USB-модем или VPN-программа на хосте, которая не перехватывает весь трафик (например, Radmin VPN)."
}
func (ifaceProvider) Fields() []Field {
	return []Field{{Key: "interface", Label: "Интерфейс", Kind: "interface", Required: true}}
}

func (ifaceProvider) Outbound(c *config.Connection) (map[string]any, error) {
	return map[string]any{"type": "direct", "interface-name": c.P("interface"), "udp": true}, nil
}
