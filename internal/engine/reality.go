package engine

import (
	"strings"

	"vpner/internal/config"
	"vpner/internal/providers"
)

// REALITY servers do not agree on the TLS hello they answer. Xray-core from
// autumn 2026 on answers only a hello that offers the X25519MLKEM768 key
// exchange, as current browsers do, and sends any other to the decoy site
// ("REALITY authentication failed" on our side). Servers from before
// mid-2025 are the other way round: they break on such a hello when the
// decoy site picks that key exchange. The engine sends the older hello
// unless told otherwise, and nothing in a share link says which one the
// server wants.
//
// So VPNer finds out by trying. Every REALITY outbound whose hello is ours
// to choose gets a twin with the other hello. Nothing is routed to the twin;
// the monitor probes it when the outbound itself does not answer, and if the
// twin does, the connection is switched and the choice is remembered in its
// ParamRealityHello.
const (
	// ParamRealityHello is the connection parameter with the hello that
	// worked last: RealityHelloPQ, or empty for the older one.
	ParamRealityHello = "realityHello"
	RealityHelloPQ    = "pq"

	realityOpts   = "reality-opts"
	realityPQOpt  = "support-x25519mlkem768"
	realityTwinPf = "alt-"
)

// RealityTwin names the twin of an outbound.
func RealityTwin(name string) string { return realityTwinPf + name }

func isRealityTwin(name string) bool { return strings.HasPrefix(name, realityTwinPf) }

// realityChoice returns the REALITY options of an outbound when its hello is
// VPNer's to choose: it is REALITY and its source (a proxy written by hand
// in YAML) does not set the key exchange itself.
func realityChoice(out map[string]any) (map[string]any, bool) {
	ro, ok := out[realityOpts].(map[string]any)
	if !ok {
		return nil, false
	}
	if _, fixed := ro[realityPQOpt]; fixed {
		return nil, false
	}
	return ro, true
}

// applyRealityHello gives out the hello remembered for connection c and
// returns its twin with the other one, or nil when there is nothing to
// choose. out must already have its name and dialer.
func applyRealityHello(out map[string]any, c *config.Connection) map[string]any {
	ro, ok := realityChoice(out)
	if !ok {
		return nil
	}
	pq := c != nil && c.P(ParamRealityHello) == RealityHelloPQ
	with := func(pq bool) map[string]any {
		m := copyMap(ro)
		if pq {
			m[realityPQOpt] = true
		}
		return m
	}
	twin := copyMap(out)
	twin["name"] = RealityTwin(out["name"].(string))
	twin[realityOpts] = with(!pq)
	out[realityOpts] = with(pq)
	return twin
}

// RealityOwner returns the id of the connection whose ParamRealityHello
// decides the hello of outbound id (a connection or a chain), or "" when
// that outbound has no twin. For a chain it is the connection of its last
// hop: the copy named after the chain.
func RealityOwner(cfg *config.Config, id string) string {
	c := cfg.Conn(id)
	if c == nil {
		return ""
	}
	var out map[string]any
	var err error
	if c.Type == config.TypeChain {
		hops := c.Hops()
		if len(hops) < 2 {
			return ""
		}
		hop := cfg.Conn(hops[len(hops)-1])
		if hop == nil || !providers.CanFollow(hop) {
			return ""
		}
		out, err = providers.HopOutbound(c, hop)
		c = hop
	} else {
		p, perr := providers.Get(c.Type)
		if perr != nil {
			return ""
		}
		np, ok := p.(providers.NativeProvider)
		if !ok {
			return ""
		}
		out, err = np.Outbound(c)
	}
	if err != nil {
		return ""
	}
	if _, ok := realityChoice(out); !ok {
		return ""
	}
	return c.ID
}
