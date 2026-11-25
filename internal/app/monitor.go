package app

import (
	"vpner/internal/i18n"

	"errors"
	"strings"
	"time"

	"vpner/internal/config"
	"vpner/internal/engine"
	"vpner/internal/providers"
	"vpner/internal/winutil"
)

// nativeHealth tracks probes of a built-in connection (AmneziaWG, VLESS...).
type nativeHealth struct {
	fails       int
	lastOK      time.Time
	lastRecover time.Time
	recovers    int // forced reconnects since it last answered
	down        bool
}

const (
	probeURL        = "http://cp.cloudflare.com/generate_204"
	probeInterval   = 10 * time.Second
	probeTimeout    = 8 * time.Second
	recoverAfter    = 3                // consecutive failed probes
	recoverPause    = 2 * time.Minute  // between forced reconnects of one connection
	recoverPauseMax = 15 * time.Minute // a server this network cannot reach is not rebuilt every 2 minutes
)

// recoverWait is the pause before the next forced reconnect: it doubles
// with every reconnect that did not help.
func recoverWait(recovers int) time.Duration {
	d := recoverPause
	for i := 0; i < recovers && d < recoverPauseMax; i++ {
		d *= 2
	}
	return min(d, recoverPauseMax)
}

// monitor runs while routing is on: it probes built-in connections and
// rebuilds them when they stop answering (a stalled AmneziaWG/WireGuard
// session does not always recover by itself), and it watches for other VPN
// programs that take over the default route and fight with VPNer.
func (a *App) monitor(m *engine.Mihomo, stop <-chan struct{}) {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		a.checkForeign()
		a.probeNative(m)
		a.probeVMs(m)
	}
}

func (a *App) checkForeign() {
	found := winutil.ForeignVPNs()
	a.mu.Lock()
	changed := strings.Join(found, ",") != strings.Join(a.foreign, ",")
	a.foreign = found
	a.mu.Unlock()
	if changed {
		if len(found) > 0 {
			a.Log.Warnf("app", i18n.T("app.anotherVpnRunsAlongsideVpner"), strings.Join(found, ", "))
		}
		a.notify()
	}
}

func (a *App) probeNative(m *engine.Mihomo) {
	cfg := a.Config()
	needRecover := []string{}
	restart := map[string]bool{} // tunnel processes to rebuild, only those
	reload := false              // connections that live in the routing engine
	switchHello := map[string]bool{}
	for _, c := range cfg.Connections {
		if !c.Enabled {
			continue
		}
		p, err := providers.Get(c.Type)
		if err != nil || p.Runtime() != providers.RuntimeNative || c.Type == "interface" {
			continue
		}
		_, err = m.Delay(c.ID, probeURL, probeTimeout)
		if err != nil {
			// A REALITY server that wants the other hello (see
			// engine/reality.go): its twin answers. Switching is all it
			// takes, so this is not counted as a failure.
			if owner := engine.RealityOwner(cfg, c.ID); owner != "" {
				if _, terr := m.Delay(engine.RealityTwin(c.ID), probeURL, probeTimeout); terr == nil {
					switchHello[owner] = true
					continue
				}
			}
		}
		a.mu.Lock()
		h := a.health[c.ID]
		if h == nil {
			h = &nativeHealth{}
			a.health[c.ID] = h
		}
		if err == nil {
			wasDown := h.down
			h.fails, h.down, h.lastOK, h.recovers = 0, false, time.Now(), 0
			a.mu.Unlock()
			if wasDown {
				a.Log.Infof(c.ID, i18n.T("app.respondsAgain"), c.Name)
				a.notify()
			}
			continue
		}
		h.fails++
		if h.fails >= recoverAfter && !h.down {
			h.down = true
			a.mu.Unlock()
			a.Log.Warnf(c.ID, i18n.T("app.doesNotRespond"), c.Name, err)
			a.notify()
			a.mu.Lock()
		}
		if h.fails < recoverAfter || time.Since(h.lastRecover) <= recoverWait(h.recovers) {
			a.mu.Unlock()
			continue
		}
		a.mu.Unlock()
		// A chain whose first hop does not answer is not rebuilt: the
		// trouble is in that hop (a VPN program in a VM without a working
		// server, say), and rebuilding the chain cannot help.
		if c.Type == config.TypeChain {
			if hops := c.Hops(); len(hops) > 0 && !a.hopAnswers(m, hops[0]) {
				continue
			}
		}
		a.mu.Lock()
		h.lastRecover = time.Now()
		h.recovers++
		needRecover = append(needRecover, c.Name)
		tunnel := a.tuns[c.ID] != nil
		if c.Type == config.TypeChain {
			for _, ch := range engine.Chains(cfg) {
				for _, st := range ch.Steps {
					if ch.ID == c.ID && st.Tunnel {
						restart[st.Name] = true
						tunnel = true
					}
				}
			}
		}
		if a.tuns[c.ID] != nil {
			restart[c.ID] = true
		}
		if !tunnel {
			reload = true
		}
		a.mu.Unlock()
	}
	a.switchRealityHello(switchHello)
	if len(needRecover) == 0 {
		return
	}
	a.Log.Warnf("app", i18n.T("app.reconnecting"), strings.Join(needRecover, ", "))
	var errs []error
	if len(restart) > 0 {
		// New processes for those tunnels only: fresh handshakes from new
		// UDP ports, nothing of the stalled session survives, and every
		// other tunnel keeps its traffic.
		errs = append(errs, a.restartTunnels(restart))
	}
	if reload {
		errs = append(errs, m.Reload())
	}
	if err := errors.Join(errs...); err != nil {
		a.Log.Errorf("app", i18n.T("app.reconnecting2"), err)
	}
}

// toggleRealityHello switches the connections ids of cfg to the other
// REALITY hello and returns the ones it changed.
func toggleRealityHello(cfg *config.Config, ids map[string]bool) []*config.Connection {
	var out []*config.Connection
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		if !ids[c.ID] {
			continue
		}
		if c.P(engine.ParamRealityHello) == engine.RealityHelloPQ {
			delete(c.Params, engine.ParamRealityHello)
		} else {
			if c.Params == nil {
				c.Params = map[string]string{}
			}
			c.Params[engine.ParamRealityHello] = engine.RealityHelloPQ
		}
		out = append(out, c)
	}
	return out
}

// switchRealityHello moves connections to the REALITY hello their server
// answers (the twin answered, the connection did not) and remembers it.
func (a *App) switchRealityHello(ids map[string]bool) {
	if len(ids) == 0 {
		return
	}
	// The settings are being changed or routing is being stopped right now:
	// the next probe tries again.
	if !a.ops.TryLock() {
		return
	}
	defer a.ops.Unlock()
	cfg := a.Config()
	changed := toggleRealityHello(cfg, ids)
	if len(changed) == 0 {
		return
	}
	if err := a.commit(cfg); err != nil {
		a.Log.Errorf("app", i18n.T("app.reconnecting2"), err)
		return
	}
	for _, c := range changed {
		kind := i18n.T("app.realityHelloClassic")
		if c.P(engine.ParamRealityHello) == engine.RealityHelloPQ {
			kind = i18n.T("app.realityHelloPQ")
		}
		a.Log.Infof(c.ID, i18n.T("app.realityHelloSwitched"), c.Name, kind)
	}
}

// hopAnswers reports whether the first hop of a chain passes traffic. A hop
// that is a built-in connection has its own probes; others (a VM, a WSL
// container) are probed here.
func (a *App) hopAnswers(m *engine.Mihomo, id string) bool {
	a.mu.Lock()
	h := a.health[id]
	a.mu.Unlock()
	if h != nil {
		return !h.down
	}
	_, err := m.Delay(id, probeURL, probeTimeout)
	return err == nil
}

// nativeState reports the health of a built-in connection for the UI.
func (a *App) nativeStateLocked(id string) (string, string) {
	if h := a.health[id]; h != nil && h.down {
		return "down", i18n.T("app.noAnswerThroughThisConnection")
	}
	return "ready", ""
}
