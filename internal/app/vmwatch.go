package app

import (
	"time"

	"vpner/internal/engine"
	"vpner/internal/hyperv"
	"vpner/internal/i18n"
)

// A VPN app that VPNer runs in a VM can end up "connected" with nothing
// passing through it: INCY sometimes cannot start its core again while its
// old helper still holds the ports, and then no server works until the VM
// restarts. VMs made by this version fix that inside (see hyperv/apps.go);
// for the others, and for whatever else gets stuck in there, VPNer restarts
// the VM when its tunnel is up but passes nothing for a few minutes. A
// server that is simply unreachable looks the same, so the restarts get
// rarer and stop after a few.
const (
	vmUpGrace      = 90 * time.Second // after the tunnel appears, before it is judged
	vmDeadAfter    = 3 * time.Minute  // passing nothing this long
	vmRestartMax   = 3                // restarts in a row that did not help
	vmRestartPause = 5 * time.Minute  // before the second restart, then x3
)

type vmHealth struct {
	failSince   time.Time // first failed probe of this streak
	restarts    int       // restarts since the VM last passed traffic
	lastRestart time.Time
	gaveUp      bool
	busy        bool // a restart is running
}

// vmRestartWait is the pause after the n-th restart before the next one:
// 5, 15, 45 minutes...
func vmRestartWait(n int) time.Duration {
	d := vmRestartPause
	for i := 1; i < n; i++ {
		d *= 3
	}
	return d
}

// step takes one probe result and says whether to restart the VM now, or
// to report that VPNer stops trying.
func (h *vmHealth) step(now time.Time, ok bool) (restart, giveUp bool) {
	if ok {
		*h = vmHealth{}
		return false, false
	}
	if h.busy {
		return false, false
	}
	if h.failSince.IsZero() {
		h.failSince = now
		return false, false
	}
	if now.Sub(h.failSince) < vmDeadAfter {
		return false, false
	}
	if h.restarts >= vmRestartMax {
		if !h.gaveUp {
			h.gaveUp = true
			return false, true
		}
		return false, false
	}
	if h.restarts > 0 && now.Sub(h.lastRestart) < vmRestartWait(h.restarts) {
		return false, false
	}
	h.restarts++
	h.lastRestart = now
	h.failSince = time.Time{}
	return true, false
}

// probeVMs checks the VMs whose VPN app VPNer runs (it reconnects by itself
// after a restart) and restarts one whose tunnel passes nothing.
func (a *App) probeVMs(m *engine.Mihomo) {
	type vm struct{ id, name string }
	var list []vm
	now := time.Now()
	a.mu.Lock()
	for id, rt := range a.vms {
		h := a.vmHealth[id]
		if h == nil {
			h = &vmHealth{}
			a.vmHealth[id] = h
		}
		r := a.conns[id]
		if r == nil || r.State != "up" || now.Sub(time.Unix(r.Since, 0)) < vmUpGrace {
			h.failSince = time.Time{} // booting or connecting: not judged yet
			continue
		}
		list = append(list, vm{id, rt.name})
	}
	a.mu.Unlock()
	for _, v := range list {
		if a.vmApp(v.id) == "" {
			continue // the user's own app may need them in the VM window
		}
		_, err := m.Delay(v.id, probeURL, probeTimeout)
		a.mu.Lock()
		h := a.vmHealth[v.id]
		if h == nil {
			a.mu.Unlock()
			continue
		}
		restart, giveUp := h.step(time.Now(), err == nil)
		n := h.restarts
		if restart {
			h.busy = true
		}
		a.mu.Unlock()
		name := v.id
		if c := a.Config().Conn(v.id); c != nil {
			name = c.Name
		}
		if giveUp {
			a.Log.Warnf(v.id, i18n.T("app.vmRestartGaveUp"), name, vmRestartMax)
			continue
		}
		if !restart {
			continue
		}
		a.Log.Warnf(v.id, i18n.T("app.vmRestarting"), name, int(vmDeadAfter.Minutes()), n, vmRestartMax)
		go func(id, vmName string) {
			err := hyperv.Restart(vmName)
			if err != nil {
				a.Log.Errorf(id, i18n.T("app.vmRestartFailed"), err)
			}
			a.mu.Lock()
			if h := a.vmHealth[id]; h != nil {
				h.busy = false
				h.failSince = time.Time{}
			}
			a.mu.Unlock()
		}(v.id, v.name)
	}
}
