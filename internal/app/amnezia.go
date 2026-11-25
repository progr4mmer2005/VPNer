package app

import (
	"vpner/internal/i18n"

	"fmt"
	"strings"

	"vpner/internal/amnezia"
	"vpner/internal/config"
	"vpner/internal/providers"
)

// provisionAmnezia creates VPNer's own client on the user's Amnezia server
// for "full access" connections that do not have one yet.
func (a *App) provisionAmnezia(c *config.Connection) error {
	if c.Type != "amnezia-server" || strings.TrimSpace(c.S("config")) != "" {
		return nil
	}
	k, err := amnezia.ParseAdminKey(c.S("key"))
	if err != nil {
		return err
	}
	name := strings.TrimSpace(c.P("clientName"))
	if name == "" {
		name = "VPNer"
	}
	a.progress(fmt.Sprintf(i18n.T("app.creatingUserOnAmneziaServer"), name), 0, -1)
	defer a.clearProgress()
	res, err := amnezia.AddClient(k, name, c.P("hostKey"), func(s string) { a.Log.Infof("app", "Amnezia: %s", s) })
	if err != nil {
		return fmt.Errorf(i18n.T("app.amneziaServer"), err)
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	c.Secrets["config"] = res.Config
	c.Params["clientId"] = res.ClientID
	c.Params["clientIp"] = res.IP
	c.Params["hostKey"] = res.HostKey
	return nil
}

// removeAmneziaClient deletes VPNer's client from the server (best effort).
func (a *App) removeAmneziaClient(c config.Connection) {
	if c.Type != "amnezia-server" || c.P("clientId") == "" {
		return
	}
	k, err := amnezia.ParseAdminKey(c.S("key"))
	if err != nil {
		return
	}
	if err := amnezia.RemoveClient(k, c.P("clientId"), c.P("hostKey")); err != nil {
		a.Log.Warnf("app", i18n.T("app.couldNotRemoveVpnerUser"), err)
		return
	}
	a.Log.Infof("app", "%s", i18n.T("app.vpnerUserWasRemovedFrom"))
}

// provisionChainKeys gives every Amnezia server hop after the first its own
// user on the server for this chain (see providers.OwnKey), and removes the
// users of hops that left the chain. Users are created only for a chain
// that is on, when it is saved.
func (a *App) provisionChainKeys(c *config.Connection, cfg *config.Config) error {
	if c.Type != config.TypeChain {
		return nil
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	hops := c.Hops()
	want := map[string]bool{}
	for i, h := range hops {
		if hc := cfg.Conn(h); i > 0 && hc != nil && providers.OwnKey(hc) {
			want[h] = true
		}
	}
	// Users of hops no longer in the chain.
	for k, id := range c.Secrets {
		hop, ok := strings.CutPrefix(k, "hopClient.")
		if !ok || want[hop] {
			continue
		}
		if hc := cfg.Conn(hop); hc != nil && !chainClientShared(cfg, c.ID, k, id) {
			go a.removeChainClient(*hc, id)
		}
		delete(c.Secrets, k)
		delete(c.Secrets, providers.ChainKeySecret(hop))
	}
	if !c.Enabled {
		return nil
	}
	for _, h := range hops {
		if !want[h] || c.S(providers.ChainKeySecret(h)) != "" {
			continue
		}
		hc := cfg.Conn(h)
		k, err := amnezia.ParseAdminKey(hc.S("key"))
		if err != nil {
			return fmt.Errorf("%s: %w", hc.Name, err)
		}
		base := strings.TrimSpace(hc.P("clientName"))
		if base == "" {
			base = "VPNer"
		}
		name := fmt.Sprintf("%s (%s)", base, c.Name)
		a.progress(fmt.Sprintf(i18n.T("app.creatingUserOnAmneziaServer"), name), 0, -1)
		res, err := amnezia.AddClient(k, name, hc.P("hostKey"), func(s string) { a.Log.Infof("app", "Amnezia: %s", s) })
		a.clearProgress()
		if err != nil {
			return fmt.Errorf(i18n.T("app.amneziaServer"), err)
		}
		c.Secrets[providers.ChainKeySecret(h)] = res.Config
		c.Secrets[providers.ChainClientSecret(h)] = res.ClientID
		a.Log.Infof("app", i18n.T("app.chainOwnUserCreated"), name, hc.Name)
	}
	return nil
}

// removeChainClients deletes the server users of a chain (best effort).
func (a *App) removeChainClients(chain config.Connection, cfg *config.Config) {
	for k, id := range chain.Secrets {
		if hop, ok := strings.CutPrefix(k, "hopClient."); ok {
			if hc := cfg.Conn(hop); hc != nil {
				a.removeChainClient(*hc, id)
			}
		}
	}
}

// removeChainClient deletes one chain user from the hop's server.
func (a *App) removeChainClient(hop config.Connection, clientID string) {
	k, err := amnezia.ParseAdminKey(hop.S("key"))
	if err != nil || clientID == "" {
		return
	}
	if err := amnezia.RemoveClient(k, clientID, hop.P("hostKey")); err != nil {
		a.Log.Warnf("app", i18n.T("app.couldNotRemoveVpnerUser"), err)
		return
	}
	a.Log.Infof("app", i18n.T("app.chainOwnUserRemoved"), hop.Name)
}

// chainClientShared: a waiting preset has the same chain with the same
// server user, so that user must stay on the server.
func chainClientShared(cfg *config.Config, chainID, key, value string) bool {
	for _, p := range cfg.Presets {
		for _, c := range p.Connections {
			if c.ID == chainID && c.Secrets[key] == value {
				return true
			}
		}
	}
	return false
}
