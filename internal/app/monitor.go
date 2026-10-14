package app

import (
	"strings"
	"time"

	"vpner/internal/engine"
	"vpner/internal/providers"
	"vpner/internal/winutil"
)

// nativeHealth tracks probes of a built-in connection (AmneziaWG, VLESS...).
type nativeHealth struct {
	fails       int
	lastOK      time.Time
	lastRecover time.Time
	down        bool
}

const (
	probeURL      = "http://cp.cloudflare.com/generate_204"
	probeInterval = 10 * time.Second
	probeTimeout  = 8 * time.Second
	recoverAfter  = 3               // consecutive failed probes
	recoverPause  = 2 * time.Minute // between forced reconnects of one connection
)

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
			a.Log.Warnf("app", "одновременно с VPNer работает другой VPN: %s — он перехватывает трафик и мешает подключениям VPNer", strings.Join(found, ", "))
		}
		a.notify()
	}
}

func (a *App) probeNative(m *engine.Mihomo) {
	cfg := a.Config()
	needRecover := []string{}
	tunnels := false
	for _, c := range cfg.Connections {
		if !c.Enabled {
			continue
		}
		p, err := providers.Get(c.Type)
		if err != nil || p.Runtime() != providers.RuntimeNative || c.Type == "interface" {
			continue
		}
		_, err = m.Delay(c.ID, probeURL, probeTimeout)
		a.mu.Lock()
		h := a.health[c.ID]
		if h == nil {
			h = &nativeHealth{}
			a.health[c.ID] = h
		}
		if err == nil {
			wasDown := h.down
			h.fails, h.down, h.lastOK = 0, false, time.Now()
			a.mu.Unlock()
			if wasDown {
				a.Log.Infof(c.ID, "«%s» снова отвечает", c.Name)
				a.notify()
			}
			continue
		}
		h.fails++
		if h.fails >= recoverAfter && !h.down {
			h.down = true
			a.mu.Unlock()
			a.Log.Warnf(c.ID, "«%s» не отвечает (%v)", c.Name, err)
			a.notify()
			a.mu.Lock()
		}
		if h.fails >= recoverAfter && time.Since(h.lastRecover) > recoverPause {
			h.lastRecover = time.Now()
			needRecover = append(needRecover, c.Name)
			if a.tun != nil && a.tun.ids[c.ID] {
				tunnels = true
			}
		}
		a.mu.Unlock()
	}
	if len(needRecover) == 0 {
		return
	}
	a.Log.Warnf("app", "переподключаю: %s", strings.Join(needRecover, ", "))
	var err error
	if tunnels {
		// A new tunnel process: fresh handshakes from new UDP ports, and
		// nothing of the stalled session survives.
		err = a.restartTunnels()
	} else {
		err = m.Reload()
	}
	if err != nil {
		a.Log.Errorf("app", "переподключение: %v", err)
	}
}

// nativeState reports the health of a built-in connection for the UI.
func (a *App) nativeStateLocked(id string) (string, string) {
	if h := a.health[id]; h != nil && h.down {
		return "down", "нет ответа через это подключение — переподключаю автоматически"
	}
	return "ready", ""
}
