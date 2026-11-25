package amnezia

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

const xrayServerConf = `{
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {"flow": "xtls-rprx-vision", "id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"},
                    {"flow": "xtls-rprx-vision", "id": "11111111-2222-3333-4444-555555555555"}
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "realitySettings": {
                    "dest": "www.googletagmanager.com:443",
                    "privateKey": "PRIV",
                    "serverNames": ["www.googletagmanager.com"],
                    "shortIds": ["6ba85179e30d4fc2"]
                },
                "security": "reality"
            }
        }
    ],
    "log": {"loglevel": "error"},
    "outbounds": [{"protocol": "freedom"}]
}`

// The name that leads to the server itself: its own domain, or a name of the
// sslip.io service built from its address.
func TestSelfName(t *testing.T) {
	for host, want := range map[string]string{
		"203.0.113.7":      "203-0-113-7.sslip.io",
		"vpn.Example.com.": "vpn.example.com",
		"2001:db8::1":      "2001-db8--1.sslip.io",
	} {
		if got := SelfName(host); got != want {
			t.Errorf("SelfName(%q) = %q, want %q", host, got, want)
		}
	}
}

// The server's own name is added next to the decoy name; everything else in
// the config — users, keys, the decoy site — stays exactly as it was.
func TestXRayAddName(t *testing.T) {
	out, in, changed, err := xrayAddName(xrayServerConf, "203-0-113-7.sslip.io")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if in.Port != 443 || in.Flow != "xtls-rprx-vision" || len(in.Names) != 2 {
		t.Fatalf("inbound = %+v", in)
	}
	var was, now map[string]any
	if err := json.Unmarshal([]byte(xrayServerConf), &was); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &now); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, out)
	}
	reality := func(m map[string]any) map[string]any {
		return m["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	}
	names := reality(now)["serverNames"].([]any)
	if len(names) != 2 || names[0] != "www.googletagmanager.com" || names[1] != "203-0-113-7.sslip.io" {
		t.Fatalf("serverNames = %v", names)
	}
	// Apart from the names, the two configs are the same.
	reality(now)["serverNames"] = reality(was)["serverNames"]
	a, _ := json.Marshal(was)
	b, _ := json.Marshal(now)
	if string(a) != string(b) {
		t.Fatalf("config changed beyond the names:\n%s\n%s", a, b)
	}
	if !strings.Contains(out, `"port": 443`) {
		t.Errorf("the port must stay a number: %s", out)
	}

	// A second run finds the name and leaves the server alone.
	again, _, changed, err := xrayAddName(out, "203-0-113-7.SSLIP.io")
	if err != nil || changed || again != out {
		t.Fatalf("second run: changed=%v err=%v", changed, err)
	}
}

func TestXRayAddNameErrors(t *testing.T) {
	if _, _, _, err := xrayAddName("not json", "a.example"); err == nil {
		t.Error("broken config must be an error")
	}
	if _, _, _, err := xrayAddName(`{"inbounds":[{"port":443,"protocol":"vless","streamSettings":{"security":"tls"}}]}`, "a.example"); err == nil {
		t.Error("a config without REALITY must be an error")
	}
}

// The link carries the server's own name and the keys of its first user.
func TestXRayLink(t *testing.T) {
	link := xrayLink("203.0.113.7", xrayInbound{Port: 443, Flow: "xtls-rprx-vision"}, "UUID", "PUB", "SID", "203-0-113-7.sslip.io", "My server · XRay")
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "vless" || u.User.Username() != "UUID" || u.Host != "203.0.113.7:443" {
		t.Fatalf("link = %s", link)
	}
	for k, want := range map[string]string{"security": "reality", "sni": "203-0-113-7.sslip.io", "pbk": "PUB", "sid": "SID", "flow": "xtls-rprx-vision", "fp": "chrome", "type": "tcp"} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if u.Fragment != "My server · XRay" {
		t.Errorf("title = %q", u.Fragment)
	}
}

func TestXRayNewHello(t *testing.T) {
	for v, want := range map[string]bool{
		"Xray 26.10.31 (Xray, Penetrates Everything.) a4a3dff (go1.27.3 linux/amd64)\nA unified platform": true,
		"Xray 26.9.1 (Xray)":  true,
		"Xray 26.8.30 (Xray)": false,
		"Xray 1.8.24 (Xray)":  false,
		"Xray 27.1.0":         true,
		"":                    false,
		"sh: xray: not found": false,
	} {
		if got := xrayNewHello(v); got != want {
			t.Errorf("xrayNewHello(%q) = %v, want %v", v, got, want)
		}
	}
}
