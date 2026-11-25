package providers

import (
	"strings"
	"testing"

	"vpner/internal/config"
)

const chainWG = `[Interface]
PrivateKey = %s
Address = 10.8.0.%s/32

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0
`

func chainConf(priv, ip string) string {
	return strings.Replace(strings.Replace(chainWG, "%s", priv, 1), "%s", ip, 1)
}

// An Amnezia server hop runs in a chain with the chain's own user, never
// with the key of the connection itself.
func TestHopOutboundOwnKey(t *testing.T) {
	key := amneziaKey(t, map[string]any{
		"containers":       []any{map[string]any{"container": "amnezia-awg2", "awg": map[string]any{"port": "30591"}}},
		"defaultContainer": "amnezia-awg2", "hostName": "5.6.7.8", "userName": "root", "password": "x", "port": 22,
	})
	own := "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	chainKey := "4CKj0Hb3hyeIgPpAzpmXYsjnNSMfTwVGSdHnZpd9C1E="
	hop := &config.Connection{ID: "cam", Name: "Amnezia", Type: "amnezia-server", Enabled: true,
		Params:  map[string]string{"clientName": "VPNer"},
		Secrets: map[string]string{"key": key, "config": chainConf(own, "2")}}
	chain := &config.Connection{ID: "cch", Name: "Chain", Type: config.TypeChain, Enabled: true,
		Params: map[string]string{"hops": "cin,cam"}, Secrets: map[string]string{}}

	if _, err := HopOutbound(chain, hop); err == nil {
		t.Fatal("without its own user the hop must not be built")
	}
	chain.Secrets[ChainKeySecret("cam")] = chainConf(chainKey, "3")
	out, err := HopOutbound(chain, hop)
	if err != nil {
		t.Fatal(err)
	}
	if out["private-key"] != chainKey {
		t.Errorf("hop must use the chain's key, got %v", out["private-key"])
	}
	if hop.S("config") != chainConf(own, "2") {
		t.Error("the connection itself must stay unchanged")
	}

	// Other built-in hops are used as they are.
	link := &config.Connection{ID: "cnl", Name: "NL", Type: "link", Enabled: true,
		Secrets: map[string]string{"link": "trojan://pass@nl.example.com:443?sni=nl.example.com#NL"}}
	if out, err := HopOutbound(chain, link); err != nil || out["type"] != "trojan" {
		t.Errorf("link hop: %v %v", out, err)
	}
}
