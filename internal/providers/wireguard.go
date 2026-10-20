package providers

import (
	"vpner/internal/i18n"

	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"vpner/internal/config"
)

// WireGuard and AmneziaWG (all obfuscation generations) run natively inside
// the routing engine: no extra process, no adapter on the host.
type wireguardProvider struct{}

func init() { Register(wireguardProvider{}) }

func (wireguardProvider) Type() string     { return "wireguard" }
func (wireguardProvider) Title() string    { return "WireGuard / AmneziaWG" }
func (wireguardProvider) Runtime() Runtime { return RuntimeNative }
func (wireguardProvider) Description() string {
	return i18n.T("providers.wireguardOrAmneziawgConfConfig")
}

func (wireguardProvider) Fields() []Field {
	return []Field{
		{Key: "config", Label: i18n.T("providers.configConfOrVpnKey"), Kind: "textarea", Secret: true, Required: true,
			Placeholder: "[Interface]\nPrivateKey = ...\nAddress = 10.8.0.2/32\nDNS = 1.1.1.1\nJc = 4\n...\n\n[Peer]\nPublicKey = ...\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0"},
		{Key: "mtu", Label: i18n.T("providers.mtuEmptyFromConfig"), Kind: "number", Advanced: true},
	}
}

type wgConf struct {
	Iface map[string]string
	Peers []map[string]string
}

func parseWGConf(text string) (*wgConf, error) {
	c := &wgConf{Iface: map[string]string{}}
	var cur map[string]string
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i == 0 {
			continue
		}
		if line == "" {
			continue
		}
		switch strings.ToLower(line) {
		case "[interface]":
			cur = c.Iface
			continue
		case "[peer]":
			cur = map[string]string{}
			c.Peers = append(c.Peers, cur)
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if prev, ok := cur[k]; ok && (k == "address" || k == "allowedips" || k == "dns") {
			v = prev + "," + v
		}
		cur[k] = v
	}
	if c.Iface["privatekey"] == "" {
		return nil, errors.New(i18n.T("providers.configHasNoInterfacePrivatekey"))
	}
	if len(c.Peers) == 0 {
		return nil, errors.New(i18n.T("providers.configHasNoPeerSection"))
	}
	for i, p := range c.Peers {
		if p["publickey"] == "" || p["endpoint"] == "" {
			return nil, fmt.Errorf(i18n.T("providers.peerPublickeyAndEndpointAre"), i+1)
		}
	}
	return c, nil
}

func splitHostPortDefault(ep string) (string, int, error) {
	h, p, err := net.SplitHostPort(ep)
	if err != nil {
		return "", 0, fmt.Errorf("Endpoint %q: %v", ep, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf(i18n.T("providers.endpointInvalidPort"), ep)
	}
	return h, port, nil
}

func numOrString(v string) any {
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return v
}

func (wireguardProvider) configText(c *config.Connection) (string, error) {
	t := strings.TrimSpace(c.S("config"))
	if strings.HasPrefix(t, "vpn://") {
		conf, _, err := decodeAmneziaKey(t)
		return conf, err
	}
	return t, nil
}

func (p wireguardProvider) Outbound(c *config.Connection) (map[string]any, error) {
	text, err := p.configText(c)
	if err != nil {
		return nil, err
	}
	wc, err := parseWGConf(text)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"type":               "wireguard",
		"private-key":        wc.Iface["privatekey"],
		"udp":                true,
		"remote-dns-resolve": true,
	}
	for _, a := range splitList(wc.Iface["address"]) {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			ip = net.ParseIP(a)
		}
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			if _, ok := out["ip"]; !ok {
				out["ip"] = ip.String()
			}
		} else if _, ok := out["ipv6"]; !ok {
			out["ipv6"] = ip.String()
		}
	}
	if _, ok := out["ip"]; !ok {
		return nil, errors.New(i18n.T("providers.addressHasNoIpv4Address"))
	}
	// Without an IPv6 address inside the tunnel, resolve and dial IPv4 only;
	// otherwise every connection first waits for an IPv6 attempt to fail.
	if _, ok := out["ipv6"]; ok {
		out["ip-version"] = "ipv4-prefer"
	} else {
		out["ip-version"] = "ipv4"
	}
	var dns []string
	for _, d := range splitList(wc.Iface["dns"]) {
		if net.ParseIP(d) != nil {
			dns = append(dns, d)
		}
	}
	if len(dns) == 0 {
		dns = []string{"1.1.1.1", "8.8.8.8"}
	}
	out["dns"] = dns
	mtu := c.P("mtu")
	if mtu == "" {
		mtu = wc.Iface["mtu"]
	}
	if n, err := strconv.Atoi(mtu); err == nil && n > 0 {
		out["mtu"] = n
	}

	peer := func(pm map[string]string) (map[string]any, error) {
		host, port, err := splitHostPortDefault(pm["endpoint"])
		if err != nil {
			return nil, err
		}
		m := map[string]any{"server": host, "port": port, "public-key": pm["publickey"]}
		if v := pm["presharedkey"]; v != "" {
			m["pre-shared-key"] = v
		}
		allowed := splitList(pm["allowedips"])
		if len(allowed) == 0 {
			allowed = []string{"0.0.0.0/0", "::/0"}
		}
		m["allowed-ips"] = allowed
		return m, nil
	}
	if len(wc.Peers) == 1 {
		m, err := peer(wc.Peers[0])
		if err != nil {
			return nil, err
		}
		for k, v := range m {
			out[k] = v
		}
	} else {
		var peers []map[string]any
		for _, pm := range wc.Peers {
			m, err := peer(pm)
			if err != nil {
				return nil, err
			}
			peers = append(peers, m)
		}
		out["peers"] = peers
	}
	// AmneziaWG 3 may give ranges ("25-35"); the engine takes one number.
	if ka, err := strconv.Atoi(strings.TrimSpace(strings.Split(wc.Peers[0]["persistentkeepalive"], "-")[0])); err == nil && ka > 0 {
		out["persistent-keepalive"] = ka
	}

	// AmneziaWG obfuscation parameters.
	awg := map[string]any{}
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "itime"} {
		if v := wc.Iface[k]; v != "" {
			awg[k] = numOrString(v)
		}
	}
	for _, k := range []string{"i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3"} {
		if v := wc.Iface[k]; v != "" {
			awg[k] = v
		}
	}
	// AmneziaWG 3.x: header protection, padding, randomized timers.
	v3 := false
	for confKey, opt := range map[string]string{
		"headerprotectionkey": "header-protection-key", "contentpaddingaddition": "content-padding-addition",
		"rekeyaftertime": "rekey-after-time", "rekeytimeout": "rekey-timeout", "rejectaftertime": "reject-after-time",
		"keepalivetimeout": "keepalive-timeout", "maxhandshakeattempts": "max-handshake-attempts",
	} {
		if v := wc.Iface[confKey]; v != "" {
			awg[opt] = v
			v3 = true
		}
	}
	for confKey, opt := range map[string]string{"randomtrailers": "random-trailers", "disablecookies": "disable-cookies"} {
		if v := strings.ToLower(wc.Iface[confKey]); v != "" {
			awg[opt] = v == "on" || v == "true" || v == "1" || v == "yes"
			v3 = true
		}
	}
	if pv := wc.Iface["protocolversion"]; strings.HasPrefix(pv, "3") {
		v3 = true
	}
	if v3 {
		awg["version"] = 3
		// v1.5-only options cannot be combined with v3
		for _, k := range []string{"j1", "j2", "j3", "itime"} {
			delete(awg, k)
		}
	}
	if len(awg) > 0 {
		out["amnezia-wg-option"] = awg
		// AmneziaVPN uses 1376 by default; the engine default (1408) is too big
		// once the obfuscation padding is added.
		if _, ok := out["mtu"]; !ok {
			out["mtu"] = 1376
		}
	}
	return out, nil
}

func (p wireguardProvider) ServerHosts(c *config.Connection) []string {
	text, err := p.configText(c)
	if err != nil {
		return nil
	}
	wc, err := parseWGConf(text)
	if err != nil {
		return nil
	}
	var out []string
	for _, pm := range wc.Peers {
		if h, _, err := splitHostPortDefault(pm["endpoint"]); err == nil {
			out = append(out, h)
		}
	}
	return out
}

func (wireguardProvider) Detect(filename, data string) bool {
	return strings.HasPrefix(data, "vpn://") ||
		(strings.Contains(strings.ToLower(data), "[interface]") && strings.Contains(strings.ToLower(data), "privatekey"))
}

func (p wireguardProvider) Import(filename, data string) (*config.Connection, error) {
	name := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	conf := data
	if strings.HasPrefix(data, "vpn://") {
		var desc string
		var err error
		conf, desc, err = decodeAmneziaKey(data)
		if err != nil {
			return nil, err
		}
		if desc != "" {
			name = desc
		}
	}
	c := &config.Connection{Secrets: map[string]string{"config": conf}, Params: map[string]string{}}
	if _, err := p.Outbound(c); err != nil {
		return nil, err
	}
	if name == "" || name == "." {
		name = "WireGuard"
		if strings.Contains(strings.ToLower(conf), "jc") {
			name = "AmneziaWG"
		}
	}
	c.Name = name
	return c, nil
}

// decodeAmneziaKey unpacks an AmneziaVPN "vpn://" share key and extracts a
// WireGuard/AmneziaWG config from it.
func decodeAmneziaKey(key string) (conf, desc string, err error) {
	raw := strings.TrimSpace(strings.TrimPrefix(key, "vpn://"))
	var b []byte
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err = enc.DecodeString(raw); err == nil {
			break
		}
	}
	if err != nil {
		return "", "", errors.New(i18n.T("providers.vpnKeyInvalidBase64"))
	}
	var js []byte
	if len(b) > 4 {
		// Qt qCompress: 4-byte big-endian length + zlib stream
		if zr, zerr := zlib.NewReader(bytes.NewReader(b[4:])); zerr == nil {
			js, _ = io.ReadAll(zr)
		}
	}
	if len(js) == 0 {
		if zr, zerr := zlib.NewReader(bytes.NewReader(b)); zerr == nil {
			js, _ = io.ReadAll(zr)
		}
	}
	if len(js) == 0 {
		js = b
	}
	var root any
	if err := json.Unmarshal(js, &root); err != nil {
		return "", "", fmt.Errorf(i18n.T("providers.vpnKeyNotJson"), err)
	}
	rootMap, _ := root.(map[string]any)
	if d, ok := rootMap["description"].(string); ok {
		desc = d
	}
	// Preferred path: containers[].{awg|wireguard}.last_config is a JSON
	// string with the client config template and the values to fill in.
	if conts, ok := rootMap["containers"].([]any); ok {
		def, _ := rootMap["defaultContainer"].(string)
		var cands []map[string]any
		for _, ci := range conts {
			cm, _ := ci.(map[string]any)
			if cm == nil {
				continue
			}
			if name, _ := cm["container"].(string); name == def {
				cands = append([]map[string]any{cm}, cands...)
			} else {
				cands = append(cands, cm)
			}
		}
		for _, cm := range cands {
			for _, proto := range []string{"awg", "wireguard"} {
				pm, _ := cm[proto].(map[string]any)
				if pm == nil {
					continue
				}
				var lc map[string]any
				if s, ok := pm["last_config"].(string); ok {
					json.Unmarshal([]byte(s), &lc)
				}
				tmpl, _ := lc["config"].(string)
				if !strings.Contains(strings.ToLower(tmpl), "[interface]") {
					continue
				}
				conf, err := fillAmneziaTemplate(tmpl, lc, pm, rootMap)
				if err == nil {
					conf = withAmneziaExtras(conf, lc, pm)
				}
				return conf, desc, err
			}
		}
	}
	// Fallback: any embedded WireGuard config.
	var found string
	var walk func(v any)
	walk = func(v any) {
		if found != "" {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for _, x := range t {
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		case string:
			low := strings.ToLower(t)
			if strings.Contains(low, "[interface]") && strings.Contains(low, "privatekey") {
				found = t
				return
			}
			if strings.HasPrefix(strings.TrimSpace(t), "{") {
				var inner any
				if json.Unmarshal([]byte(t), &inner) == nil {
					walk(inner)
				}
			}
		}
	}
	walk(root)
	if found == "" {
		if _, ok := rootMap["userName"]; ok {
			return "", desc, errors.New(i18n.T("providers.thisIsFullAccessKey"))
		}
		return "", desc, errors.New(i18n.T("providers.noWireguardAmneziawgConfigFound"))
	}
	conf, err = fillAmneziaTemplate(found, rootMap)
	return conf, desc, err
}

// Amnezia keeps the client config as a template; these placeholders are
// filled from the same key, exactly like the AmneziaVPN app does.
var amneziaVars = map[string][]string{
	"PRIMARY_DNS":                   {"dns1"},
	"SECONDARY_DNS":                 {"dns2"},
	"WIREGUARD_CLIENT_IP":           {"client_ip"},
	"WIREGUARD_CLIENT_PRIVATE_KEY":  {"client_priv_key"},
	"WIREGUARD_SERVER_PUBLIC_KEY":   {"server_pub_key"},
	"WIREGUARD_PSK":                 {"psk_key"},
	"SERVER_IP_ADDRESS":             {"hostName"},
	"AWG_SERVER_PORT":               {"port"},
	"WIREGUARD_SERVER_PORT":         {"port"},
	"JUNK_PACKET_COUNT":             {"Jc"},
	"JUNK_PACKET_MIN_SIZE":          {"Jmin"},
	"JUNK_PACKET_MAX_SIZE":          {"Jmax"},
	"INIT_PACKET_JUNK_SIZE":         {"S1"},
	"RESPONSE_PACKET_JUNK_SIZE":     {"S2"},
	"COOKIE_REPLY_PACKET_JUNK_SIZE": {"S3"},
	"TRANSPORT_PACKET_JUNK_SIZE":    {"S4"},
	"INIT_PACKET_MAGIC_HEADER":      {"H1"},
	"RESPONSE_PACKET_MAGIC_HEADER":  {"H2"},
	"UNDERLOAD_PACKET_MAGIC_HEADER": {"H3"},
	"TRANSPORT_PACKET_MAGIC_HEADER": {"H4"},
	"SPECIAL_JUNK_1":                {"I1"},
	"SPECIAL_JUNK_2":                {"I2"},
	"SPECIAL_JUNK_3":                {"I3"},
	"SPECIAL_JUNK_4":                {"I4"},
	"SPECIAL_JUNK_5":                {"I5"},
	"CONTROLLED_JUNK_1":             {"J1"},
	"CONTROLLED_JUNK_2":             {"J2"},
	"CONTROLLED_JUNK_3":             {"J3"},
	"SPECIAL_HANDSHAKE_TIMEOUT":     {"Itime"},
	"WIREGUARD_CLIENT_MTU":          {"mtu"},
	"MTU":                           {"mtu"},
}

var amneziaVarRe = regexp.MustCompile(`\$([A-Z][A-Z0-9_]*)`)

// Lines that may be dropped when their value is unknown.
var optionalWGKeys = map[string]bool{"dns": true, "mtu": true, "i1": true, "i2": true, "i3": true, "i4": true, "i5": true,
	"j1": true, "j2": true, "j3": true, "itime": true, "s3": true, "s4": true, "persistentkeepalive": true, "presharedkey": true}

func fillAmneziaTemplate(tmpl string, sources ...map[string]any) (string, error) {
	lookup := func(name string) (string, bool) {
		fields := amneziaVars[name]
		for _, src := range sources {
			for _, f := range fields {
				for k, v := range src {
					if !strings.EqualFold(k, f) {
						continue
					}
					switch x := v.(type) {
					case string:
						if x != "" {
							return x, true
						}
					case float64:
						return strconv.FormatFloat(x, 'f', -1, 64), true
					}
				}
			}
		}
		switch name {
		case "PRIMARY_DNS":
			return "1.1.1.1", true
		case "SECONDARY_DNS":
			return "1.0.0.1", true
		}
		return "", false
	}
	var out []string
	var missing []string
	for _, line := range strings.Split(strings.ReplaceAll(tmpl, "\r\n", "\n"), "\n") {
		unresolved := false
		filled := amneziaVarRe.ReplaceAllStringFunc(line, func(m string) string {
			if v, ok := lookup(m[1:]); ok {
				return v
			}
			unresolved = true
			return m
		})
		if unresolved {
			key, _, _ := strings.Cut(strings.TrimSpace(filled), "=")
			if optionalWGKeys[strings.ToLower(strings.TrimSpace(key))] {
				continue
			}
			missing = append(missing, amneziaVarRe.FindAllString(filled, -1)...)
		}
		out = append(out, filled)
	}
	if len(missing) > 0 {
		return "", fmt.Errorf(i18n.T("providers.vpnKeyLacksValuesExport"), strings.Join(missing, ", "))
	}
	return strings.Join(out, "\n"), nil
}

// withAmneziaExtras adds values Amnezia keeps outside the config template:
// the MTU and the protocol version.
func withAmneziaExtras(conf string, lc, pm map[string]any) string {
	low := strings.ToLower(conf)
	var add []string
	if !strings.Contains(low, "\nmtu") {
		for _, src := range []map[string]any{lc, pm} {
			if v, ok := src["mtu"]; ok && fmt.Sprint(v) != "" {
				add = append(add, "MTU = "+fmt.Sprint(v))
				break
			}
		}
	}
	if v, ok := pm["protocol_version"]; ok && !strings.Contains(low, "protocolversion") {
		add = append(add, "ProtocolVersion = "+fmt.Sprint(v))
	}
	if len(add) == 0 {
		return conf
	}
	// insert right after the [Interface] header
	i := strings.Index(low, "[interface]")
	if i < 0 {
		return conf
	}
	j := i + len("[interface]")
	return conf[:j] + "\n" + strings.Join(add, "\n") + conf[j:]
}
