package engine

import (
	"fmt"

	"vpner/internal/config"
	"vpner/internal/providers"
)

// Chain is a chain connection ready to run. Traffic enters the outbound of
// the first hop as it is (that connection is shared with its own use), and
// every next hop is a copy of its connection that reaches its server
// through the previous one. The copy of the last hop is named after the
// chain, so rules and DNS servers address the chain by its id.
type Chain struct {
	ID    string
	First string // connection id of the first hop
	Steps []ChainStep
}

// ChainStep is one hop after the first.
type ChainStep struct {
	Name   string         // outbound name of the copy
	ConnID string         // the connection it copies
	Prev   string         // outbound the copy reaches its server through
	Out    map[string]any // outbound of the connection, without name
	Tunnel bool           // a stateful tunnel: it runs in the tunnel process
}

// StepName names the copy of hop i (counted from 0) of a chain; the last
// hop is the chain itself.
func StepName(chainID string, i, n int) string {
	if i == n-1 {
		return chainID
	}
	return fmt.Sprintf("%s.%d", chainID, i)
}

// Chains lists the chains that are on and whose hops all build. Only the
// first hop has to be on by itself: the next hops run as copies, so
// switching such a connection off stops its own use only. That matters for
// WireGuard/AmneziaWG, whose one key cannot run in two places at once.
func Chains(cfg *config.Config) []Chain {
	var out []Chain
	for i := range cfg.Connections {
		c := &cfg.Connections[i]
		if c.Type != config.TypeChain || !c.Enabled {
			continue
		}
		hops := c.Hops()
		if len(hops) < 2 {
			continue
		}
		first := cfg.Conn(hops[0])
		if first == nil || !first.Enabled || first.Type == config.TypeChain {
			continue
		}
		ch := Chain{ID: c.ID, First: first.ID}
		prev := first.ID
		ok := true
		for k := 1; k < len(hops); k++ {
			hc := cfg.Conn(hops[k])
			if hc == nil || !providers.CanFollow(hc) {
				ok = false
				break
			}
			o, err := providers.HopOutbound(c, hc)
			if err != nil {
				ok = false
				break
			}
			name := StepName(c.ID, k, len(hops))
			ch.Steps = append(ch.Steps, ChainStep{Name: name, ConnID: hc.ID, Prev: prev, Out: o, Tunnel: IsTunnelOutbound(o)})
			prev = name
		}
		if ok {
			out = append(out, ch)
		}
	}
	return out
}

// ChainTunnels returns the copies that run in the tunnel process (name ->
// outbound) and, for each, the outbound of the routing engine it reaches
// its server through.
func ChainTunnels(cfg *config.Config) (outs map[string]map[string]any, prev map[string]string) {
	outs, prev = map[string]map[string]any{}, map[string]string{}
	for _, ch := range Chains(cfg) {
		for _, st := range ch.Steps {
			if st.Tunnel {
				outs[st.Name] = st.Out
				prev[st.Name] = st.Prev
			}
		}
	}
	return outs, prev
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
