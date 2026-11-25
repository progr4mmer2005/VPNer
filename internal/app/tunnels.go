package app

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
	"vpner/internal/engine"
	"vpner/internal/providers"
)

// tunnelProc is a separate engine process that holds one WireGuard/AmneziaWG
// tunnel (see engine.TunnelInput for why tunnels cannot live in the routing
// engine). Every tunnel — a connection, or the copy of a connection that is a
// chain hop — has a process of its own: rebuilding one that stopped answering
// never touches the others. With one shared process, an AmneziaWG connection
// that could not reach its server from the current network was rebuilt over
// and over, and each time took down a chain that worked (and the other way
// round).
type tunnelProc struct {
	m    *engine.Mihomo
	conf string // YAML of the running config
	gen  int    // bumped on every deliberate (re)start or stop
}

// tunnelOutbounds returns the outbounds that run in tunnel processes, and for
// the copies that are chain hops the routing engine outbound each one
// reaches its server through.
func (a *App) tunnelOutbounds() (map[string]map[string]any, map[string]string) {
	outs := map[string]map[string]any{}
	cfg := a.Config()
	for _, c := range cfg.Connections {
		if !c.Enabled || c.Type == config.TypeChain {
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
	chained, prev := engine.ChainTunnels(cfg)
	for name, out := range chained {
		outs[name] = out
	}
	return outs, prev
}

// syncTunnels brings the tunnel processes in line with the configuration:
// new tunnels are started, changed ones restarted, removed ones stopped.
// restart names tunnels to restart even if nothing changed (to recover a
// stalled one); the others are left alone.
func (a *App) syncTunnels(restart map[string]bool) error {
	a.tunMu.Lock()
	defer a.tunMu.Unlock()
	outs, prev := a.tunnelOutbounds()

	a.mu.Lock()
	router := a.engine
	if a.tunUser == "" {
		a.tunUser, a.tunPass = randHex(6), randHex(16)
	}
	user, pass := a.tunUser, a.tunPass
	var gone []*tunnelProc
	for id, t := range a.tuns {
		if _, ok := outs[id]; !ok || router == nil {
			t.gen++
			gone = append(gone, t)
			delete(a.tuns, id)
		}
	}
	a.mu.Unlock()
	for _, t := range gone {
		t.m.Stop()
	}
	if router == nil {
		return nil
	}
	ids := make([]string, 0, len(outs))
	for id := range outs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		if err := a.syncTunnel(id, outs[id], prev[id], user, pass, router.Bin, restart[id]); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// syncTunnel starts or restarts the process of one tunnel. Caller holds tunMu.
func (a *App) syncTunnel(id string, out map[string]any, via, user, pass, bin string, force bool) error {
	a.mu.Lock()
	port := a.tunPorts[id]
	t := a.tuns[id]
	a.mu.Unlock()
	if port == 0 {
		p, err := freePort()
		if err != nil {
			return err
		}
		port = p
		a.mu.Lock()
		a.tunPorts[id] = p
		a.mu.Unlock()
	}
	if t == nil {
		cport, err := freePort()
		if err != nil {
			return err
		}
		t = &tunnelProc{m: &engine.Mihomo{Bin: bin, WorkDir: filepath.Join(a.engineDir(), "tunnels", id),
			Port: cport, Secret: randHex(16), Logf: a.engineLog}}
		a.mu.Lock()
		a.tuns[id] = t
		a.mu.Unlock()
	}
	// A chain hop reaches its server through the routing engine's listener
	// for the previous hop; the engine opens it on the same port.
	ups := map[string]int{}
	if via != "" {
		a.mu.Lock()
		if p := a.testPortLocked(via); p != 0 {
			ups[id] = p
		}
		a.mu.Unlock()
	}
	conf := engine.GenerateTunnels(engine.TunnelInput{
		Outbounds: map[string]map[string]any{id: out}, Ports: map[string]int{id: port}, Upstreams: ups,
		User: user, Pass: pass, ControllerPort: t.m.Port, Secret: t.m.Secret})
	b, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	a.mu.Lock()
	same := string(b) == t.conf
	a.mu.Unlock()
	if !force && same && t.m.Running() {
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
	a.mu.Lock()
	t.conf = string(b)
	a.mu.Unlock()
	go a.watchTunnel(id, t, gen)
	return nil
}

// watchTunnel restarts a tunnel process if it exits by itself.
func (a *App) watchTunnel(id string, t *tunnelProc, gen int) {
	<-t.m.Exited()
	time.Sleep(2 * time.Second)
	a.mu.Lock()
	cur := a.tuns[id] == t && t.gen == gen && a.running
	a.mu.Unlock()
	if !cur || t.m.Running() {
		return
	}
	a.Log.Errorf(id, "%s", i18n.T("app.tunnelProcessExitedUnexpectedlyRestartin"))
	if err := a.syncTunnels(map[string]bool{id: true}); err != nil {
		a.Log.Errorf(id, i18n.T("app.restartingTunnels"), err)
	}
}

// restartTunnels recreates the named tunnels from scratch (new process, new
// handshakes). Their SOCKS ports stay the same, so the routing engine needs
// no reload, and the other tunnels keep running.
func (a *App) restartTunnels(ids map[string]bool) error { return a.syncTunnels(ids) }

// stopTunnels ends every tunnel process.
func (a *App) stopTunnels() {
	a.mu.Lock()
	var all []*tunnelProc
	for id, t := range a.tuns {
		t.gen++
		all = append(all, t)
		delete(a.tuns, id)
	}
	a.mu.Unlock()
	for _, t := range all {
		t.m.Stop()
	}
}

// tunnelEndpointsLocked lists the SOCKS5 endpoints of running tunnels.
// Caller holds a.mu.
func (a *App) tunnelEndpointsLocked() map[string]engine.LocalEndpoint {
	eps := map[string]engine.LocalEndpoint{}
	for id, t := range a.tuns {
		if t.conf != "" && t.m.Running() {
			eps[id] = engine.LocalEndpoint{Port: a.tunPorts[id], User: a.tunUser, Pass: a.tunPass}
		}
	}
	return eps
}

// isTunnel reports whether a connection (or chain hop copy) runs in a tunnel
// process.
func (a *App) isTunnel(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tuns[id] != nil
}
