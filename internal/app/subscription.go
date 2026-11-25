package app

import (
	"errors"
	"fmt"
	"strings"

	"vpner/internal/config"
	"vpner/internal/i18n"
	"vpner/internal/importer"
	"vpner/internal/providers"
)

// A subscription connection keeps the servers of a provider subscription
// and runs through the one the user chose (providers/subscription.go). A
// server can be taken out as a connection of its own and put back; what is
// taken out is part of the config, so every preset remembers it.

// fetchSubServers downloads the subscription of c and stores its servers in
// it. The servers taken out of it get their new links too.
func (a *App) fetchSubServers(c *config.Connection, cfg *config.Config) error {
	body, src, err := a.FetchSubscription(c.S(providers.SecretSubURL), c.P(providers.ParamSubAs))
	if err != nil {
		return err
	}
	if SubscriptionStub("subscription", body) {
		msg := i18n.T("web.subStub")
		if c.P(providers.ParamSubAs) == SubAsClient {
			msg = i18n.T("web.subStubTryIncy")
		}
		return errors.New(msg)
	}
	res, err := importer.Parse("subscription", body)
	if err != nil {
		return err
	}
	var list []providers.SubServer
	for _, x := range res.Connections {
		if x.Type == "link" && x.S("link") != "" {
			list = append(list, providers.SubServer{Name: x.Name, Link: x.S("link")})
		}
	}
	if len(list) == 0 {
		return errors.New(i18n.T("app.subNoServers"))
	}
	providers.SetSubServers(c, providers.SubKeys(list))
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	c.Params[providers.ParamSubTitle] = src.Title
	c.Params[ParamSub], c.Params[ParamSubName] = src.ID, src.Title
	if strings.TrimSpace(c.Name) == "" {
		c.Name = src.Title
	}
	byKey := map[string]providers.SubServer{}
	for _, s := range providers.SubServers(c) {
		byKey[s.Key] = s
	}
	for i := range cfg.Connections {
		x := &cfg.Connections[i]
		if x.P(providers.ParamSubOf) == c.ID {
			if s, ok := byKey[x.P(providers.ParamSubKey)]; ok {
				x.Secrets["link"] = s.Link
			}
		}
	}
	a.Log.Infof("app", i18n.T("app.subUpdated"), c.Name, len(list))
	return nil
}

func (a *App) subConn(cfg *config.Config, id string) (*config.Connection, error) {
	c := cfg.Conn(id)
	if c == nil {
		return nil, fmt.Errorf(i18n.T("app.connectionNotFound"), id)
	}
	if c.Type != providers.TypeSubscription {
		return nil, errors.New(i18n.T("app.notSubscription"))
	}
	return c, nil
}

// RefreshSubscription downloads the subscription's servers again.
func (a *App) RefreshSubscription(id string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	c, err := a.subConn(cfg, id)
	if err != nil {
		return err
	}
	a.progress(i18n.T("app.subUpdating"), 0, -1)
	defer a.clearProgress()
	if err := a.fetchSubServers(c, cfg); err != nil {
		return err
	}
	return a.commit(cfg)
}

// SelectSubServer makes the subscription run through the server key.
func (a *App) SelectSubServer(id, key string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	c, err := a.subConn(cfg, id)
	if err != nil {
		return err
	}
	found := false
	for _, s := range providers.SubServers(c) {
		found = found || s.Key == key
	}
	if !found {
		return errors.New(i18n.T("app.subServerNotFound"))
	}
	c.Params[providers.ParamSubServer] = key
	return a.commit(cfg)
}

// takenOut finds the connection a server was taken out as.
func takenOut(cfg *config.Config, subID, key string) *config.Connection {
	for i := range cfg.Connections {
		x := &cfg.Connections[i]
		if x.P(providers.ParamSubOf) == subID && x.P(providers.ParamSubKey) == key {
			return x
		}
	}
	return nil
}

// ExtractSubServers takes servers out as connections of their own (all of
// them when keys is empty). They start off: two servers of one subscription
// at once may be against the service's terms, and the window says so when
// one is turned on.
func (a *App) ExtractSubServers(id string, keys []string) ([]string, error) {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	c, err := a.subConn(cfg, id)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	var ids []string
	for _, s := range providers.SubServers(c) {
		if len(keys) > 0 && !want[s.Key] {
			continue
		}
		if x := takenOut(cfg, id, s.Key); x != nil {
			ids = append(ids, x.ID)
			continue
		}
		n := config.Connection{ID: config.NewID("c"), Name: s.Name, Type: "link",
			Params: map[string]string{providers.ParamSubOf: id, providers.ParamSubKey: s.Key,
				ParamSub: c.P(ParamSub), ParamSubName: c.P(ParamSubName)},
			Secrets: map[string]string{"link": s.Link}}
		cfg.Connections = append(cfg.Connections, n)
		ids = append(ids, n.ID)
	}
	if err := a.commit(cfg); err != nil {
		return nil, err
	}
	return ids, nil
}

// RetractSubServers puts servers back into their subscription (all of them
// when keys is empty): rules, chains and DNS servers that used one of them
// use the subscription from now on, so nothing starts blocking.
func (a *App) RetractSubServers(id string, keys []string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	if _, err := a.subConn(cfg, id); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, k := range keys {
		want[k] = true
	}
	gone := map[string]bool{}
	var kept []config.Connection
	for _, x := range cfg.Connections {
		if x.P(providers.ParamSubOf) == id && (len(keys) == 0 || want[x.P(providers.ParamSubKey)]) {
			gone[x.ID] = true
			continue
		}
		kept = append(kept, x)
	}
	if len(gone) == 0 {
		return nil
	}
	for g := range gone {
		a.disconnect(g, false)
	}
	cfg.Connections = kept
	retarget(cfg, gone, id)
	return a.commit(cfg)
}

// retarget points everything that used the connections in gone at to.
func retarget(cfg *config.Config, gone map[string]bool, to string) {
	for i := range cfg.Rules {
		if gone[cfg.Rules[i].Target] {
			cfg.Rules[i].Target = to
		}
	}
	if gone[cfg.Settings.FinalTarget] {
		cfg.Settings.FinalTarget = to
	}
	for i := range cfg.DNS.Servers {
		if gone[cfg.DNS.Servers[i].Via] {
			cfg.DNS.Servers[i].Via = to
		}
	}
	for i := range cfg.Connections {
		ch := &cfg.Connections[i]
		if ch.Type != config.TypeChain {
			continue
		}
		hops := ch.Hops()
		changed := false
		for j, h := range hops {
			if gone[h] {
				hops[j], changed = to, true
			}
		}
		if changed {
			ch.SetHops(dedupe(hops))
		}
	}
}

func dedupe(ids []string) []string {
	var out []string
	for i, x := range ids {
		if i == 0 || ids[i-1] != x {
			out = append(out, x)
		}
	}
	return out
}

// SubView is a subscription as the window shows it: no links or keys.
type SubView struct {
	Title    string          `json:"title"`
	Selected string          `json:"selected"`
	Servers  []SubServerView `json:"servers"`
}

type SubServerView struct {
	Key   string `json:"key"`
	Name  string `json:"name"`
	Proto string `json:"proto"`           // vless/reality, vless/ws…
	Taken string `json:"taken,omitempty"` // the connection it was taken out as
}

// SubscriptionView describes a subscription connection for the window.
func SubscriptionView(cfg *config.Config, c *config.Connection) *SubView {
	if c.Type != providers.TypeSubscription {
		return nil
	}
	v := &SubView{Title: c.P(providers.ParamSubTitle)}
	if s, ok := providers.SubSelected(c); ok {
		v.Selected = s.Key
	}
	for _, s := range providers.SubServers(c) {
		sv := SubServerView{Key: s.Key, Name: s.Name, Proto: providers.LinkProto(s.Link)}
		if x := takenOut(cfg, c.ID, s.Key); x != nil {
			sv.Taken = x.ID
		}
		v.Servers = append(v.Servers, sv)
	}
	return v
}
