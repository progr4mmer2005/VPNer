package providers

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"vpner/internal/config"
)

// An XRay client config as the AmneziaVPN app builds it
// (xrayConfigurator.cpp), with test values.
const testXRayConfig = `{"log":{"loglevel":"error"},
 "inbounds":[{"listen":"127.0.0.1","port":"10808","protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless",
   "settings":{"vnext":[{"address":"203.0.113.7","port":443,
     "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality",
     "realitySettings":{"fingerprint":"chrome","serverName":"www.example.com",
       "publicKey":"PUBKEY","shortId":"abcd","spiderX":""}}}]}`

// testKey packs JSON the way AmneziaVPN does: qCompress, base64url.
func testKey(t *testing.T, root any) string {
	t.Helper()
	js, _ := json.Marshal(root)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(js)
	w.Close()
	b := make([]byte, 4, 4+z.Len())
	binary.BigEndian.PutUint32(b, uint32(len(js)))
	return "vpn://" + base64.RawURLEncoding.EncodeToString(append(b, z.Bytes()...))
}

func checkVless(t *testing.T, link string) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "vless" || u.User.Username() != "11111111-2222-3333-4444-555555555555" || u.Host != "203.0.113.7:443" {
		t.Fatalf("link %q", link)
	}
	q := u.Query()
	for k, want := range map[string]string{"security": "reality", "sni": "www.example.com", "pbk": "PUBKEY", "sid": "abcd", "fp": "chrome", "flow": "xtls-rprx-vision", "type": "tcp"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if _, _, err := parseLink(link); err != nil {
		t.Errorf("VPNer does not read its own link: %v", err)
	}
}

// A vpn:// key shared for XRay becomes a VLESS link connection, whether
// last_config is the config itself or holds it under "config".
func TestImportAmneziaXRayKey(t *testing.T) {
	inner, _ := json.Marshal(map[string]any{"config": testXRayConfig})
	for _, lc := range []string{testXRayConfig, string(inner)} {
		key := testKey(t, map[string]any{"description": "Friend", "defaultContainer": "amnezia-xray",
			"containers": []any{map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": lc}}}})
		c, err := Import("", key)
		if err != nil {
			t.Fatal(err)
		}
		if c.Type != "link" || c.Name != "Friend" {
			t.Fatalf("type %q name %q", c.Type, c.Name)
		}
		checkVless(t, c.S("link"))
	}
}

// A key with AmneziaWG as its default stays AmneziaWG.
func TestAmneziaKeyPrefersDefault(t *testing.T) {
	root := map[string]any{"defaultContainer": "amnezia-awg", "containers": []any{
		map[string]any{"container": "amnezia-awg", "awg": map[string]any{}},
		map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": testXRayConfig}},
	}}
	if _, ok := amneziaXRayKey(root); ok {
		t.Fatal("XRay taken over the default AmneziaWG")
	}
	root["defaultContainer"] = "amnezia-xray"
	if _, ok := amneziaXRayKey(root); !ok {
		t.Fatal("default XRay not taken")
	}
}

// "XRay native format" (the .json file) is accepted as it is.
func TestImportXRayJSON(t *testing.T) {
	c, err := Import("amnezia_for_xray.json", testXRayConfig)
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != "link" {
		t.Fatalf("type %q", c.Type)
	}
	checkVless(t, c.S("link"))
	if xrayJSON(`{"vpner":1}`) != nil || xrayJSON(`{"outbounds":[{"protocol":"freedom"}]}`) != nil {
		t.Error("other JSON taken for XRay")
	}
}

// The chain editor learns which hops run over UDP and whether a REALITY
// hop carries a name that points to its server.
func TestHopNet(t *testing.T) {
	link := func(l string) *config.Connection {
		return &config.Connection{Type: "link", Secrets: map[string]string{"link": l}}
	}
	if n := HopNet(&config.Connection{Type: "amnezia-server"}); n == nil || !n.UDP {
		t.Error("amnezia-server not UDP")
	}
	if n := HopNet(link("hysteria2://pass@203.0.113.7:443?sni=a.example#x")); n == nil || !n.UDP {
		t.Error("hysteria2 not UDP")
	}
	decoy := "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?security=reality&sni=www.example.com&pbk=PUBKEY&sid=abcd&type=tcp#x"
	n := HopNet(link(decoy))
	if n == nil || !n.Reality || n.SNISelf || n.SNI != "www.example.com" || n.SelfName != "203-0-113-7.sslip.io" {
		t.Fatalf("decoy: %+v", n)
	}
	n = HopNet(link(strings.Replace(decoy, "www.example.com", "203-0-113-7.sslip.io", 1)))
	if n == nil || !n.SNISelf {
		t.Fatalf("own name: %+v", n)
	}
	if HopNet(link("trojan://pw@203.0.113.7:443?sni=a.example#x")) != nil {
		t.Error("plain TLS hop flagged")
	}
}

// An XRay config with REALITY over gRPC, as VPN providers give them out
// ("show config" in their apps), keeps its gRPC service name.
func TestImportXRayJSONGRPC(t *testing.T) {
	js := `{"outbounds":[{"protocol":"vless","tag":"proxy",
	  "settings":{"vnext":[{"address":"vpn.example.net","port":443,"users":[{"encryption":"none","id":"11111111-2222-3333-4444-555555555555","flow":""}]}]},
	  "streamSettings":{"network":"grpc","security":"reality",
	    "grpcSettings":{"mode":false,"authority":"","serviceName":"svc.Name"},
	    "realitySettings":{"shortId":"abcd","fingerprint":"firefox","serverName":"cdn.example.org","publicKey":"PUBKEY"}}},
	  {"protocol":"freedom","tag":"direct"}],
	  "inbounds":[{"protocol":"socks","port":10808,"sniffing":{"enabled":true,"routeOnly":false,"destOverride":["http","tls"]}}]}`
	c, err := Import("", js)
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := parseLink(c.S("link"))
	if err != nil {
		t.Fatal(err)
	}
	g, _ := m["grpc-opts"].(map[string]any)
	if m["network"] != "grpc" || g["grpc-service-name"] != "svc.Name" || m["client-fingerprint"] != "firefox" || m["servername"] != "cdn.example.org" {
		t.Fatalf("%v", m)
	}
}
