package providers

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"vpner/internal/config"
)

// amneziaKey builds a key the way AmneziaVPN does: qCompress(JSON), base64url.
func amneziaKey(t *testing.T, root any) string {
	js, _ := json.Marshal(root)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(js)
	w.Close()
	b := binary.BigEndian.AppendUint32(nil, uint32(len(js)))
	return "vpn://" + base64.RawURLEncoding.EncodeToString(append(b, z.Bytes()...))
}

const tmpl = `[Interface]
Address = $WIREGUARD_CLIENT_IP/32
DNS = $PRIMARY_DNS, $SECONDARY_DNS
PrivateKey = $WIREGUARD_CLIENT_PRIVATE_KEY
Jc = $JUNK_PACKET_COUNT
Jmin = $JUNK_PACKET_MIN_SIZE
Jmax = $JUNK_PACKET_MAX_SIZE
S1 = $INIT_PACKET_JUNK_SIZE
S2 = $RESPONSE_PACKET_JUNK_SIZE
H1 = $INIT_PACKET_MAGIC_HEADER
H2 = $RESPONSE_PACKET_MAGIC_HEADER
H3 = $UNDERLOAD_PACKET_MAGIC_HEADER
H4 = $TRANSPORT_PACKET_MAGIC_HEADER
I1 = $SPECIAL_JUNK_1

[Peer]
PublicKey = $WIREGUARD_SERVER_PUBLIC_KEY
PresharedKey = $WIREGUARD_PSK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $SERVER_IP_ADDRESS:$AWG_SERVER_PORT
PersistentKeepalive = 25
`

func TestAmneziaTemplateKey(t *testing.T) {
	last := map[string]any{
		"config": tmpl, "client_ip": "10.8.1.5", "client_priv_key": "eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=",
		"server_pub_key": "Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=", "psk_key": "31aIhAPwktDGpH4JDhA8GNvjFXEf/a6+UaQRyOAiyfM=",
		"hostName": "5.6.7.8", "port": 34567,
	}
	lc, _ := json.Marshal(last)
	root := map[string]any{
		"containers": []any{map[string]any{"container": "amnezia-awg", "awg": map[string]any{
			"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "20", "S2": "30", "H1": "111", "H2": "222", "H3": "333", "H4": "444",
			"last_config": string(lc), "port": "34567", "transport_proto": "udp"}}},
		"defaultContainer": "amnezia-awg", "description": "AmneziaVPN Kansas-City",
		"dns1": "1.1.1.1", "dns2": "1.0.0.1", "hostName": "5.6.7.8",
	}
	key := amneziaKey(t, root)
	c, err := Import("amnezia_config.vpn", key)
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != "wireguard" || c.Name != "AmneziaVPN Kansas-City" {
		t.Errorf("type=%s name=%q", c.Type, c.Name)
	}
	c.ID = "x"
	out, err := wireguardProvider{}.Outbound(c)
	if err != nil {
		t.Fatal(err)
	}
	if out["ip"] != "10.8.1.5" || out["server"] != "5.6.7.8" || out["port"] != 34567 {
		t.Errorf("outbound: ip=%v server=%v port=%v", out["ip"], out["server"], out["port"])
	}
	awg := out["amnezia-wg-option"].(map[string]any)
	if awg["jc"] != 4 || awg["h4"] != 444 {
		t.Errorf("awg options: %v", awg)
	}
	if _, has := awg["i1"]; has {
		t.Error("missing optional I1 must be dropped, not kept as a placeholder")
	}
	if dns := strings.Join(out["dns"].([]string), ","); dns != "1.1.1.1,1.0.0.1" {
		t.Errorf("dns = %s", dns)
	}
}

func TestAmneziaFullAccessKeyRejected(t *testing.T) {
	key := amneziaKey(t, map[string]any{"containers": []any{}, "hostName": "5.6.7.8", "userName": "root", "password": "x", "port": 22})
	_, err := Import("full.vpn", key)
	if err == nil || !strings.Contains(err.Error(), "полного доступа") {
		t.Errorf("full-access key should be refused with a clear message, got %v", err)
	}
	_ = config.TargetDirect
}

func TestAmneziaWG3Options(t *testing.T) {
	conf := `[Interface]
Address = 10.8.1.9/32
PrivateKey = eCtXsJZ27+4PbhDkHnB923tkUn2Gj59wZw5wFA75MnU=
Jc = 6
S1 = 12
S3 = 12
H1 = 1
I1 = <r 2><b 0x8580>
HeaderProtectionKey = MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
RekeyAfterTime = 100-120
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = Cr8hWlKvtDt7nrvf+f0brNQQzabAqrjfBvas9pmowjo=
AllowedIPs = 0.0.0.0/0
Endpoint = 5.6.7.8:30591
PersistentKeepalive = 25-35
`
	c := &config.Connection{Secrets: map[string]string{"config": conf}, Params: map[string]string{}}
	out, err := wireguardProvider{}.Outbound(c)
	if err != nil {
		t.Fatal(err)
	}
	opt := out["amnezia-wg-option"].(map[string]any)
	if opt["version"] != 3 || opt["header-protection-key"] == nil || opt["random-trailers"] != true || opt["reject-after-time"] != "150-180" {
		t.Errorf("v3 options not passed: %v", opt)
	}
	if out["persistent-keepalive"] != 25 || out["mtu"] != 1376 {
		t.Errorf("keepalive=%v mtu=%v", out["persistent-keepalive"], out["mtu"])
	}
}
