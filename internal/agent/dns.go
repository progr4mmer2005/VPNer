//go:build linux

package agent

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// tunnelResolver resolves names for traffic that the host sends into a VPN.
// Queries are sent from a socket inside the connection namespace, so they can
// only travel through the tunnel, to the DNS servers the VPN provided.
type tunnelResolver struct {
	id      string
	servers func() []string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func newTunnelResolver(id string, servers func() []string) *tunnelResolver {
	return &tunnelResolver{id: id, servers: servers, cache: map[string]cacheEntry{}}
}

func (r *tunnelResolver) flush() {
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
}

func (r *tunnelResolver) LookupIPv4(name string) ([]net.IP, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}
	r.mu.Lock()
	if e, ok := r.cache[name]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.ips, nil
	}
	r.mu.Unlock()

	servers := r.servers()
	if len(servers) == 0 {
		return nil, errors.New("resolve: VPN provided no DNS servers")
	}
	var lastErr error
	for _, s := range servers {
		ips, ttl, err := r.query(s, name)
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %s: no such host", name)
		}
		if ttl < 30 {
			ttl = 30
		}
		if ttl > 3600 {
			ttl = 3600
		}
		r.mu.Lock()
		r.cache[name] = cacheEntry{ips: ips, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
		r.mu.Unlock()
		return ips, nil
	}
	return nil, fmt.Errorf("resolve %s: %v", name, lastErr)
}

func (r *tunnelResolver) query(server, name string) ([]net.IP, uint32, error) {
	return r.queryWith(server, name, func(network, addr string) (net.Conn, error) {
		var c net.Conn
		err := inNetns(r.id, func() error {
			var e error
			c, e = net.DialTimeout(network, addr, 4*time.Second)
			return e
		})
		return c, err
	})
}

// queryWith performs an A query; dial decides where the socket lives.
func (r *tunnelResolver) queryWith(server, name string, dial func(network, addr string) (net.Conn, error)) ([]net.IP, uint32, error) {
	q, id, err := buildQuery(name, dnsmessage.TypeA)
	if err != nil {
		return nil, 0, err
	}
	addr := net.JoinHostPort(server, "53")
	var resp []byte
	for _, network := range []string{"udp", "tcp"} {
		c, err := dial(network, addr)
		if err != nil {
			return nil, 0, err
		}
		c.SetDeadline(time.Now().Add(4 * time.Second))
		if network == "tcp" {
			b := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
			_, err = c.Write(append(b, q...))
		} else {
			_, err = c.Write(q)
		}
		if err == nil {
			buf := make([]byte, 65535)
			var n int
			if network == "tcp" {
				var l [2]byte
				if _, err = readFull(c, l[:]); err == nil {
					n = int(binary.BigEndian.Uint16(l[:]))
					_, err = readFull(c, buf[:n])
				}
			} else {
				n, err = c.Read(buf)
			}
			resp = buf[:n]
		}
		c.Close()
		if err != nil {
			return nil, 0, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(resp)
		if err != nil {
			return nil, 0, err
		}
		if h.ID != id {
			return nil, 0, errors.New("dns id mismatch")
		}
		if h.Truncated && network == "udp" {
			continue
		}
		if h.RCode == dnsmessage.RCodeNameError {
			return nil, 0, nil
		}
		if h.RCode != dnsmessage.RCodeSuccess {
			return nil, 0, fmt.Errorf("dns rcode %v", h.RCode)
		}
		p.SkipAllQuestions()
		var ips []net.IP
		ttl := uint32(300)
		for {
			ah, err := p.AnswerHeader()
			if err != nil {
				break
			}
			if ah.Type == dnsmessage.TypeA {
				a, err := p.AResource()
				if err != nil {
					break
				}
				ips = append(ips, net.IP(a.A[:]))
				if ah.TTL < ttl {
					ttl = ah.TTL
				}
			} else {
				p.SkipAnswer()
			}
		}
		return ips, ttl, nil
	}
	return nil, 0, errors.New("dns: no answer")
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := c.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func buildQuery(name string, t dnsmessage.Type) ([]byte, uint16, error) {
	var idb [2]byte
	rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, 0, err
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET})
	msg, err := b.Finish()
	return msg, id, err
}

// ---- stub resolver for the VPN daemon itself ----

// serveDNSStub answers A queries from processes inside the namespace (the VPN
// daemon resolving its server name) by asking the host via the bridge.
func serveDNSStub(pc net.PacketConn, lookup func(name string) ([]net.IP, error)) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)
		go func() {
			if resp := answerStub(req, lookup); resp != nil {
				pc.WriteTo(resp, from)
			}
		}()
	}
}

func answerStub(req []byte, lookup func(string) ([]net.IP, error)) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(req)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	var ips []net.IP
	if q.Type == dnsmessage.TypeA {
		ips, err = lookup(strings.TrimSuffix(q.Name.String(), "."))
		if err != nil {
			rh.RCode = dnsmessage.RCodeServerFailure
		}
	}
	b := dnsmessage.NewBuilder(nil, rh)
	b.StartQuestions()
	b.Question(q)
	b.StartAnswers()
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			var a [4]byte
			copy(a[:], ip4)
			b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 30}, dnsmessage.AResource{A: a})
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}
