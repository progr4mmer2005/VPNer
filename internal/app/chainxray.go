package app

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"

	"vpner/internal/amnezia"
	"vpner/internal/config"
	"vpner/internal/engine"
)

// ParamXRayOf marks the XRay connection VPNer made for chains out of an
// Amnezia server connection: it holds that connection's id. Setting XRay up
// again updates this connection instead of adding another.
const ParamXRayOf = "xrayOf"

// XRayHop is the answer to "set up XRay for chains".
type XRayHop struct {
	// Missing: the server has no XRay yet; the window shows how to install it.
	Missing bool   `json:"missing,omitempty"`
	ID      string `json:"id,omitempty"`   // the XRay connection to put in the chain
	Name    string `json:"name,omitempty"` // its name
	Site    string `json:"site,omitempty"` // the name the server answers for chains
	Added   bool   `json:"added,omitempty"`
}

// UpsertXRayHop puts the XRay connection for chains of the Amnezia server
// connection amn into cfg and returns it. It is off by itself: a chain runs
// its own copy of a hop, and the server's direct connections keep the decoy
// name.
func UpsertXRayHop(cfg *config.Config, amn *config.Connection, res *amnezia.XRayLink) *config.Connection {
	var c *config.Connection
	for i := range cfg.Connections {
		if x := &cfg.Connections[i]; x.Type == "link" && x.P(ParamXRayOf) == amn.ID {
			c = x
		}
	}
	if c == nil {
		cfg.Connections = append(cfg.Connections, config.Connection{
			ID: config.NewID("c"), Name: amn.Name + " · XRay", Type: "link",
			Params: map[string]string{ParamXRayOf: amn.ID}})
		c = &cfg.Connections[len(cfg.Connections)-1]
		if res.NewHello {
			c.Params[engine.ParamRealityHello] = engine.RealityHelloPQ
		}
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	c.Secrets["link"] = res.Link
	return c
}

// ChainXRay prepares the XRay way to an Amnezia server for chains (see
// amnezia/xray.go): the server's XRay learns the server's own name, and a
// link connection with that name appears, ready to be a hop.
func (a *App) ChainXRay(id string) (*XRayHop, error) {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	amn := cfg.Conn(id)
	if amn == nil {
		return nil, fmt.Errorf(i18n.T("app.connectionNotFound"), id)
	}
	if amn.Type != "amnezia-server" {
		return nil, errors.New(i18n.T("app.xrayOnlyAmneziaServer"))
	}
	k, err := amnezia.ParseAdminKey(amn.S("key"))
	if err != nil {
		return nil, err
	}
	a.progress(i18n.T("app.xraySettingUp"), 0, -1)
	defer a.clearProgress()
	res, err := amnezia.XRayForChain(k, amn.Name+" · XRay", amn.P("hostKey"), func(s string) { a.Log.Infof("app", "Amnezia: %s", s) })
	if errors.Is(err, amnezia.ErrNoXRay) {
		return &XRayHop{Missing: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf(i18n.T("app.amneziaServer"), err)
	}
	if amn.P("hostKey") == "" && res.HostKey != "" {
		if amn.Params == nil {
			amn.Params = map[string]string{}
		}
		amn.Params["hostKey"] = res.HostKey // pin the server's key, as AddClient does
	}
	c := UpsertXRayHop(cfg, amn, res)
	out := &XRayHop{ID: c.ID, Name: c.Name, Site: res.Name, Added: res.Added}
	if err := a.commit(cfg); err != nil {
		return nil, err
	}
	a.Log.Infof("app", i18n.T("app.xrayHopReady"), out.Name, amn.Name, res.Name)
	return out, nil
}
