package importer

import "testing"

// "XRay native format" from the AmneziaVPN app pasted into the window.
func TestParseXRayJSON(t *testing.T) {
	js := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.7","port":443,
	  "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},
	  "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"PUBKEY","shortId":"abcd","fingerprint":"chrome"}}}]}`
	r, err := Parse("amnezia_for_xray.json", js)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Connections) != 1 || r.Connections[0].Type != "link" {
		t.Fatalf("%+v", r)
	}
}

// A subscription in the XRay JSON format: a list of configs, one server
// each, named by their "remarks".
func TestParseXRaySubscription(t *testing.T) {
	cfg := func(name, host string) string {
		return `{"remarks":"` + name + `","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"` + host + `","port":443,
		  "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
		  "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/p","headers":{"Host":"h.example"}},"tlsSettings":{"serverName":"h.example"}}},
		  {"protocol":"freedom","tag":"direct"}]}`
	}
	r, err := Parse("subscription", "["+cfg("Sweden", "a.example")+","+cfg("Germany", "b.example")+"]")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "list" || len(r.Connections) != 2 || r.Connections[0].Name != "Sweden" || r.Connections[1].Name != "Germany" {
		t.Fatalf("%+v", r.Summary())
	}
}
