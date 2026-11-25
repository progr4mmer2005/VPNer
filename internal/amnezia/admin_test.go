package amnezia

import (
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

const serverConf = `[Interface]
PrivateKey = SERVERPRIV
Address = 10.8.1.0/24
ListenPort = 30591
Jc = 6
S1 = 12
H1 = 1
HeaderProtectionKey = HPK
RandomTrailers = on
# I1 = <r 2><b 0x8580>
# I2 = $SPECIAL_JUNK_2

[Peer]
PublicKey = PEER1
PresharedKey = PSK
AllowedIPs = 10.8.1.1/32

[Peer]
PublicKey = PEER2
PresharedKey = PSK
AllowedIPs = 10.8.1.2/32
`

func TestNextIP(t *testing.T) {
	if ip, _ := nextIP(serverConf, "10.8.1.0"); ip != "10.8.1.3" {
		t.Errorf("next ip = %s", ip)
	}
	if ip, _ := nextIP("[Interface]\nAddress = 10.8.1.0/24\n", "10.8.1.0"); ip != "10.8.1.2" {
		t.Errorf("first client ip = %s", ip)
	}
	if ip, _ := nextIP("[Peer]\nAllowedIPs = 10.8.1.254/32\n", "10.8.1.0"); ip != "10.8.2.1" {
		t.Errorf("wrap ip = %s", ip)
	}
}

func TestServerParams(t *testing.T) {
	p := serverParams(serverConf)
	if p["Jc"] != "6" || p["HeaderProtectionKey"] != "HPK" || p["I1"] != "<r 2><b 0x8580>" || p["ListenPort"] != "30591" {
		t.Errorf("params: %v", p)
	}
	if _, ok := p["I2"]; ok {
		t.Error("unfilled template values must be skipped")
	}
	if p["PublicKey"] != "" {
		t.Error("peer keys must not leak into interface params")
	}
}

func TestRemovePeer(t *testing.T) {
	out := removePeer(serverConf, "PEER2")
	if strings.Contains(out, "PEER2") || !strings.Contains(out, "PEER1") || !strings.Contains(out, "ListenPort") {
		t.Errorf("removePeer result:\n%s", out)
	}
}

func TestKeyPair(t *testing.T) {
	priv, pub, err := genKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := base64.StdEncoding.DecodeString(priv)
	want, _ := curve25519.X25519(pb, curve25519.Basepoint)
	if base64.StdEncoding.EncodeToString(want) != pub || len(pb) != 32 {
		t.Error("public key does not match private key")
	}
}
