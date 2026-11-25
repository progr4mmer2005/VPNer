package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vpner/internal/config"
	"vpner/internal/providers"
)

func subServer(t *testing.T, names ...string) *httptest.Server {
	t.Helper()
	var items []string
	for i, n := range names {
		items = append(items, `{"remarks":"`+n+`","outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.`+string(rune('1'+i))+`","port":443,
		  "users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},
		  "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"a.example","publicKey":"PUBKEY","shortId":"abcd"}}}]}`)
	}
	body := "[" + strings.Join(items, ",") + "]"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Profile-Title", "Pepper")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A subscription is one connection with its servers inside; it runs
// through the chosen one; servers are taken out as connections of their own
// and put back, and what used them then uses the subscription.
func TestSubscriptionConnection(t *testing.T) {
	a := presetApp(t)
	srv := subServer(t, "Sweden", "Germany", "Poland")
	id, err := a.SaveConnection(config.Connection{Type: providers.TypeSubscription, Enabled: true,
		Params: map[string]string{}, Secrets: map[string]string{providers.SecretSubURL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.Config()
	c := cfg.Conn(id)
	if c.Name != "Pepper" || len(providers.SubServers(c)) != 3 || c.P(ParamSub) == "" {
		t.Fatalf("subscription: %+v", c.Params)
	}
	if s, _ := providers.SubSelected(c); s.Name != "Sweden" {
		t.Fatalf("first server is not the default: %v", s.Name)
	}
	if err := a.SelectSubServer(id, "Germany"); err != nil {
		t.Fatal(err)
	}
	if s, _ := providers.SubSelected(a.Config().Conn(id)); s.Name != "Germany" {
		t.Fatal("not switched")
	}

	ids, err := a.ExtractSubServers(id, []string{"Poland"})
	if err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	pl := a.Config().Conn(ids[0])
	if pl.Type != "link" || pl.Enabled || pl.P(providers.ParamSubOf) != id || pl.P(ParamSub) != c.P(ParamSub) {
		t.Fatalf("taken out: %+v", pl)
	}
	again, _ := a.ExtractSubServers(id, []string{"Poland"})
	if len(again) != 1 || again[0] != ids[0] || len(a.Config().Connections) != 3 {
		t.Fatal("taking out twice made a second connection")
	}
	// a rule and a chain use the taken-out server
	cfg = a.Config()
	cfg.Rules = append(cfg.Rules, config.Rule{ID: "rp", Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"x.example"}, Target: pl.ID})
	ch := config.Connection{ID: "ch", Name: "chain", Type: config.TypeChain, Enabled: true, Params: map[string]string{}, Secrets: map[string]string{}}
	ch.SetHops([]string{"c1", pl.ID})
	cfg.Connections = append(cfg.Connections, ch)
	if err := a.commit(cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.RetractSubServers(id, nil); err != nil {
		t.Fatal(err)
	}
	cfg = a.Config()
	if cfg.Conn(pl.ID) != nil {
		t.Fatal("put back, but still a connection")
	}
	for _, r := range cfg.Rules {
		if r.ID == "rp" && r.Target != id {
			t.Fatalf("rule not moved to the subscription: %s", r.Target)
		}
	}
	if hops := cfg.Conn("ch").Hops(); hops[1] != id {
		t.Fatalf("chain hop not moved: %v", hops)
	}

	// the servers taken out survive the subscription's deletion on their own
	ids, _ = a.ExtractSubServers(id, nil)
	if len(ids) != 3 {
		t.Fatalf("take out all: %v", ids)
	}
	if err := a.DeleteConnection(id); err != nil {
		t.Fatal(err)
	}
	for _, x := range ids {
		if c := a.Config().Conn(x); c == nil || c.P(providers.ParamSubOf) != "" {
			t.Fatalf("server after the subscription is gone: %+v", c)
		}
	}
}

// The engine gets the chosen server of a subscription.
func TestSubscriptionOutbound(t *testing.T) {
	c := &config.Connection{Type: providers.TypeSubscription, Params: map[string]string{providers.ParamSubServer: "B"}, Secrets: map[string]string{}}
	providers.SetSubServers(c, []providers.SubServer{
		{Key: "A", Name: "A", Link: "vless://11111111-2222-3333-4444-555555555555@203.0.113.1:443?security=reality&sni=a.example&pbk=K&sid=ab&type=tcp#A"},
		{Key: "B", Name: "B", Link: "vless://11111111-2222-3333-4444-555555555555@203.0.113.2:443?security=reality&sni=a.example&pbk=K&sid=ab&type=tcp#B"},
	})
	p, _ := providers.Get(providers.TypeSubscription)
	m, err := p.(providers.NativeProvider).Outbound(c)
	if err != nil || m["server"] != "203.0.113.2" {
		t.Fatalf("%v %v", m["server"], err)
	}
	if !providers.TypeCanFollow(providers.TypeSubscription) {
		t.Error("a subscription cannot be a chain hop")
	}
}
