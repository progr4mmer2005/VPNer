package app

import (
	"vpner/internal/i18n"

	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"vpner/internal/engine"
	"vpner/internal/providers"
)

// tunnelProc is the separate engine process that holds WireGuard/AmneziaWG
// tunnels (see engine.TunnelInput for why they cannot live in the routing
// engine). It is restarted only when those connections change or one of
// them has to be recovered.
type tunnelProc struct {
	m     *engine.Mihomo
	ports map[string]int // connection id -> SOCKS5 port (stable for the session)
	user  string
	pass  string
	ids   map[string]bool // connections in the running config
	conf  string          // YAML of the running config
	gen   int             // bumped on every deliberate (re)start or stop
}

// tunnelOutbounds returns the outbounds that belong in the tunnel process.
func (a *App) tunnelOutbounds() map[string]map[string]any {
	outs := map[string]map[string]any{}
	for _, c := range a.Config().Connections {
		if !c.Enabled {
			continue
		}
		p, err := providers.Get(c.Type)
		if err != nil {
			continue
		}
		np, ok := p.(providers.NativeProvider)
		if !ok {
			continue
		}
		c := c
		out, err := np.Outbound(&c)
		if err != nil || !engine.IsTunnelOutbound(out) {
			continue // errors are reported by the routing engine config
		}
		outs[c.ID] = out
	}
	return outs
}

// syncTunnels brings the tunnel process in line with the configuration.
// force restarts it even if nothing changed (to recover a stalled tunnel).
func (a *App) syncTunnels(force bool) error {
	a.tunMu.Lock()
	defer a.tunMu.Unlock()
	outs := a.tunnelOutbounds()

	a.mu.Lock()
	t := a.tun
	router := a.engine
	a.mu.Unlock()
	if router == nil {
		return nil
	}
	if len(outs) == 0 {
		if t != nil {
			a.mu.Lock()
			t.gen++
			t.ids, t.conf = map[string]bool{}, ""
			a.mu.Unlock()
			t.m.Stop()
		}
		return nil
	}
	if t == nil {
		port, err := freePort()
		if err != nil {
			return err
		}
		t = &tunnelProc{
			m: &engine.Mihomo{Bin: router.Bin, WorkDir: filepath.Join(a.engineDir(), "tunnels"),
				Port: port, Secret: randHex(16), Logf: a.engineLog},
			ports: map[string]int{}, user: randHex(6), pass: randHex(16), ids: map[string]bool{},
		}
		a.mu.Lock()
		a.tun = t
		a.mu.Unlock()
	}
	for id := range outs {
		a.mu.Lock()
		have := t.ports[id] != 0
		a.mu.Unlock()
		if have {
			continue
		}
		p, err := freePort()
		if err != nil {
			return err
		}
		a.mu.Lock()
		t.ports[id] = p
		a.mu.Unlock()
	}
	a.mu.Lock()
	ports := map[string]int{}
	for id, p := range t.ports {
		ports[id] = p
	}
	a.mu.Unlock()
	conf := engine.GenerateTunnels(engine.TunnelInput{Outbounds: outs, Ports: ports,
		User: t.user, Pass: t.pass, ControllerPort: t.m.Port, Secret: t.m.Secret})
	b, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	if !force && t.m.Running() && string(b) == t.conf {
		return nil
	}
	if err := t.m.Test(conf); err != nil {
		return err
	}
	a.mu.Lock()
	t.gen++
	gen := t.gen
	a.mu.Unlock()
	if err := t.m.Restart(conf); err != nil {
		return err
	}
	ids := map[string]bool{}
	for id := range outs {
		ids[id] = true
	}
	a.mu.Lock()
	t.ids, t.conf = ids, string(b)
	a.mu.Unlock()
	go a.watchTunnels(t, gen)
	return nil
}

// watchTunnels restarts the tunnel process if it exits by itself.
func (a *App) watchTunnels(t *tunnelProc, gen int) {
	<-t.m.Exited()
	time.Sleep(2 * time.Second)
	a.mu.Lock()
	cur := a.tun == t && t.gen == gen && a.running
	a.mu.Unlock()
	if !cur || t.m.Running() {
		return
	}
	a.Log.Errorf("app", "%s", i18n.T("app.tunnelProcessExitedUnexpectedlyRestartin"))
	if err := a.syncTunnels(true); err != nil {
		a.Log.Errorf("app", i18n.T("app.restartingTunnels"), err)
	}
}

// restartTunnels recreates every tunnel from scratch (new process, new
// handshakes). The SOCKS ports stay the same, so the routing engine needs
// no reload.
func (a *App) restartTunnels() error { return a.syncTunnels(true) }

// stopTunnels ends the tunnel process.
func (a *App) stopTunnels() {
	a.mu.Lock()
	t := a.tun
	a.tun = nil
	if t != nil {
		t.gen++
	}
	a.mu.Unlock()
	if t != nil {
		t.m.Stop()
	}
}

// tunnelEndpointsLocked lists the SOCKS5 endpoints of running tunnels.
// Caller holds a.mu.
func (a *App) tunnelEndpointsLocked() map[string]engine.LocalEndpoint {
	eps := map[string]engine.LocalEndpoint{}
	t := a.tun
	if t == nil || !t.m.Running() {
		return eps
	}
	for id := range t.ids {
		eps[id] = engine.LocalEndpoint{Port: t.ports[id], User: t.user, Pass: t.pass}
	}
	return eps
}

// isTunnel reports whether a connection runs in the tunnel process.
func (a *App) isTunnel(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tun != nil && a.tun.ids[id]
}
