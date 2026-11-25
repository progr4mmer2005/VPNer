package app

import (
	"vpner/internal/i18n"

	"net"
	"sort"
	"strconv"
	"strings"

	"vpner/internal/config"
	"vpner/internal/engine"
)

// A rule change reaches only new connections: the engine picks the route
// when a connection opens. Programs keep their connections open for a long
// time (browsers reuse one HTTP/2 connection for a whole site), so after
// every apply the connections whose route has changed are closed and the
// programs open them again by the new rules. Connections whose route stays
// the same are left alone: closing everything would cut SSH and RDP
// sessions and long downloads.

// routes is the routing the engine was given: the configuration a config
// was generated from and the outbounds in it.
type routes struct {
	cfg   *config.Config
	known map[string]bool
}

func newRoutes(cfg *config.Config, conf map[string]any) *routes {
	return &routes{cfg: cfg, known: engine.Outbounds(conf)}
}

// outbound is the engine outbound q goes to; false when it cannot be told
// without the engine.
func (r *routes) outbound(q routeQuery) (string, bool) {
	h := route(r.cfg, q, true)
	if !h.known {
		return "", false
	}
	return engine.OutboundFor(h.target, r.known), true
}

// queryOf is what the engine's rules see of a live connection: domain rules
// use the sniffed name when there is one, IP rules the destination address.
func queryOf(c engine.Connection) routeQuery {
	md := c.Metadata
	q := routeQuery{
		host:           strings.TrimSuffix(strings.ToLower(md.SniffHost), "."),
		process:        strings.ToLower(md.Process),
		processPath:    strings.ToLower(md.ProcessPath),
		network:        strings.ToLower(md.Network),
		matchedRule:    c.Rule,
		matchedPayload: c.Payload,
	}
	if q.host == "" {
		q.host = strings.TrimSuffix(strings.ToLower(md.Host), ".")
	}
	if net.ParseIP(q.host) != nil {
		q.host = ""
	}
	q.ip = net.ParseIP(md.DestIP)
	q.port, _ = strconv.Atoi(md.DestPort)
	return q
}

// staleRoute decides whether a live connection must be closed after the
// engine switched from prev to cur (prev is nil when unknown). It returns
// the outbound the connection would take now. A connection is closed only
// when
//   - it came in through the TUN adapter and is not VPNer's own (the engine,
//     the agent, tunnel and test listeners on 127.0.0.1 are never touched);
//   - its new route is certain and differs from the outbound it uses;
//   - and this change is what moved it: if the previous rules already sent
//     it where the new ones do, it is left alone.
func staleRoute(c engine.Connection, self []string, prev, cur *routes) (string, bool) {
	md := c.Metadata
	if !strings.EqualFold(md.Type, "Tun") || len(c.Chains) == 0 {
		return "", false
	}
	for _, p := range self {
		if strings.EqualFold(md.Process, p) {
			return "", false
		}
	}
	if ip := net.ParseIP(md.DestIP); ip != nil && ip.IsLoopback() {
		return "", false
	}
	q := queryOf(c)
	now, ok := cur.outbound(q)
	if !ok || now == c.Chains[0] {
		return "", false
	}
	if prev != nil {
		if was, ok := prev.outbound(q); ok && was == now {
			return "", false
		}
	}
	return now, true
}

// rerouteLogLines caps the per-connection lines in the log.
const rerouteLogLines = 10

// reroute closes the open connections whose route changed from prev to cur.
func (a *App) reroute(m *engine.Mihomo, prev, cur *routes) {
	list, err := m.Connections()
	if err != nil {
		a.Log.Warnf("app", i18n.T("app.couldNotListConnections"), err)
		return
	}
	type change struct {
		process, dest, from, to string
		n                       int
	}
	var changes []*change
	byKey := map[string]*change{}
	closed, failed := 0, 0
	self := selfProcesses()
	for _, c := range list.Connections {
		now, ok := staleRoute(c, self, prev, cur)
		if !ok {
			continue
		}
		if err := m.CloseConnection(c.ID); err != nil {
			failed++
			continue
		}
		closed++
		dest := c.Metadata.SniffHost
		if dest == "" {
			dest = c.Metadata.Host
		}
		if dest == "" {
			dest = c.Metadata.DestIP
		}
		dest = net.JoinHostPort(dest, c.Metadata.DestPort)
		k := strings.Join([]string{c.Metadata.Process, dest, c.Chains[0], now}, "|")
		if ch := byKey[k]; ch != nil {
			ch.n++
			continue
		}
		ch := &change{process: c.Metadata.Process, dest: dest, from: a.ConnName(c.Chains[0]), to: a.ConnName(now), n: 1}
		if ch.process == "" {
			ch.process = "?"
		}
		byKey[k] = ch
		changes = append(changes, ch)
	}
	if failed > 0 {
		a.Log.Warnf("app", i18n.T("app.couldNotCloseConnections"), failed)
	}
	if closed == 0 {
		return
	}
	a.Log.Infof("app", i18n.T("app.closedConnectionsWithChangedRoute"), closed)
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].n > changes[j].n })
	for i, ch := range changes {
		if i == rerouteLogLines {
			rest := 0
			for _, ch := range changes[i:] {
				rest += ch.n
			}
			a.Log.Infof("app", i18n.T("app.andMoreConnections"), rest)
			break
		}
		if ch.n > 1 {
			a.Log.Infof("app", i18n.T("app.rerouteConnections"), ch.process, ch.dest, ch.n, ch.from, ch.to)
		} else {
			a.Log.Infof("app", i18n.T("app.rerouteConnection"), ch.process, ch.dest, ch.from, ch.to)
		}
	}
}
