// Package socks5 is a small SOCKS5 server (CONNECT + UDP ASSOCIATE, optional
// username/password auth) whose network side is pluggable. It is used on both
// ends of the bridge: on Windows it forwards into a VPN namespace, inside a
// VPN namespace it forwards the VPN daemon's own traffic out to the host.
package socks5

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpner/internal/bridge"
)

// Backend performs the real network operations.
type Backend interface {
	DialTCP(addr string) (net.Conn, error)
	OpenUDP() (UDPSession, error)
}

// UDPSession relays datagrams; Recv returns the source address of replies.
type UDPSession interface {
	Send(addr string, payload []byte) error
	Recv(buf []byte) (addr string, payload []byte, err error)
	Close() error
}

type Server struct {
	Backend Backend
	User    string // empty = no auth
	Pass    string
	Logf    func(format string, args ...any)
	UDPBind net.IP // address UDP relays bind to; defaults to the TCP listener's local IP
	// ListenUDP creates the UDP relay socket (e.g. inside a network
	// namespace); defaults to net.ListenUDP.
	ListenUDP func(addr *net.UDPAddr) (*net.UDPConn, error)
	listener  net.Listener
	wg        sync.WaitGroup
}

func (s *Server) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	} else {
		log.Printf(f, a...)
	}
}

func (s *Server) Serve(l net.Listener) error {
	s.listener = l
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(c)
		}()
	}
}

func (s *Server) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

const (
	cmdConnect   = 1
	cmdAssociate = 3
)

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(c)

	// greeting
	var hdr [2]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	want := byte(0)
	if s.User != "" {
		want = 2
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		c.Write([]byte{5, 0xff})
		return
	}
	c.Write([]byte{5, want})
	if want == 2 {
		if !s.auth(br, c) {
			return
		}
	}

	// request
	var req [3]byte
	if _, err := io.ReadFull(br, req[:]); err != nil || req[0] != 5 {
		return
	}
	addr, err := readAddr(br)
	if err != nil {
		reply(c, 1, nil)
		return
	}
	switch req[1] {
	case cmdConnect:
		up, err := s.Backend.DialTCP(addr)
		if err != nil {
			s.logf("socks connect %s: %v", addr, err)
			reply(c, errCode(err), nil)
			return
		}
		local, _ := up.LocalAddr().(*net.TCPAddr)
		if err := reply(c, 0, local); err != nil {
			up.Close()
			return
		}
		c.SetDeadline(time.Time{})
		var client io.ReadWriteCloser = c
		if br.Buffered() > 0 {
			client = &bufConn{Conn: c, r: br}
		}
		bridge.Pipe(client, up)
	case cmdAssociate:
		s.associate(c, br)
	default:
		reply(c, 7, nil)
	}
}

func (s *Server) auth(br *bufio.Reader, c net.Conn) bool {
	var v [2]byte
	if _, err := io.ReadFull(br, v[:]); err != nil || v[0] != 1 {
		return false
	}
	u := make([]byte, v[1])
	if _, err := io.ReadFull(br, u); err != nil {
		return false
	}
	var pl [1]byte
	if _, err := io.ReadFull(br, pl[:]); err != nil {
		return false
	}
	p := make([]byte, pl[0])
	if _, err := io.ReadFull(br, p); err != nil {
		return false
	}
	good := subtle.ConstantTimeCompare(u, []byte(s.User)) == 1 &&
		subtle.ConstantTimeCompare(p, []byte(s.Pass)) == 1
	if !good {
		c.Write([]byte{1, 1})
		return false
	}
	c.Write([]byte{1, 0})
	return true
}

func (s *Server) associate(c net.Conn, br *bufio.Reader) {
	bindIP := s.UDPBind
	if bindIP == nil {
		bindIP = c.LocalAddr().(*net.TCPAddr).IP
	}
	listen := s.ListenUDP
	if listen == nil {
		listen = func(a *net.UDPAddr) (*net.UDPConn, error) { return net.ListenUDP("udp", a) }
	}
	pc, err := listen(&net.UDPAddr{IP: bindIP})
	if err != nil {
		reply(c, 1, nil)
		return
	}
	defer pc.Close()
	sess, err := s.Backend.OpenUDP()
	if err != nil {
		s.logf("socks udp: %v", err)
		reply(c, errCode(err), nil)
		return
	}
	defer sess.Close()
	la := pc.LocalAddr().(*net.UDPAddr)
	if err := reply(c, 0, &net.TCPAddr{IP: la.IP, Port: la.Port}); err != nil {
		return
	}
	c.SetDeadline(time.Time{})

	clientIP := c.RemoteAddr().(*net.TCPAddr).IP
	var mu sync.Mutex
	var client *net.UDPAddr

	// replies: backend -> client
	go func() {
		buf := make([]byte, bridge.MaxDatagram)
		out := make([]byte, 0, bridge.MaxDatagram+300)
		for {
			from, payload, err := sess.Recv(buf)
			if err != nil {
				pc.Close()
				return
			}
			a, err := bridge.EncodeAddr(from)
			if err != nil {
				continue
			}
			out = append(out[:0], 0, 0, 0)
			out = append(out, a...)
			out = append(out, payload...)
			mu.Lock()
			dst := client
			mu.Unlock()
			if dst != nil {
				pc.WriteToUDP(out, dst)
			}
		}
	}()

	// requests: client -> backend
	go func() {
		buf := make([]byte, bridge.MaxDatagram)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				c.Close()
				return
			}
			if !from.IP.Equal(clientIP) || n < 4 || buf[2] != 0 { // no fragmentation support
				continue
			}
			mu.Lock()
			client = from
			mu.Unlock()
			addr, used, err := bridge.DecodeAddr(buf[3:n])
			if err != nil {
				continue
			}
			sess.Send(addr, buf[3+used:n])
		}
	}()

	// association lives as long as the TCP control connection
	io.Copy(io.Discard, br)
}

func readAddr(r io.Reader) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var host string
	switch t[0] {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		return "", errors.New("bad address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(p[0])<<8|int(p[1]))), nil
}

func reply(c net.Conn, code byte, bind *net.TCPAddr) error {
	b := []byte{5, code, 0}
	if bind != nil && bind.IP.To4() != nil {
		b = append(b, 1)
		b = append(b, bind.IP.To4()...)
		b = append(b, byte(bind.Port>>8), byte(bind.Port))
	} else if bind != nil && bind.IP != nil {
		b = append(b, 4)
		b = append(b, bind.IP.To16()...)
		b = append(b, byte(bind.Port>>8), byte(bind.Port))
	} else {
		b = append(b, 1, 0, 0, 0, 0, 0, 0)
	}
	_, err := c.Write(b)
	return err
}

// errCode maps errors to SOCKS5 reply codes (best effort).
func errCode(err error) byte {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return 6 // TTL expired ~ timeout
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return 5
	case strings.Contains(s, "unreachable"), strings.Contains(s, "not up"), strings.Contains(s, "no route"):
		return 3
	case strings.Contains(s, "no such host"), strings.Contains(s, "resolve"):
		return 4
	}
	return 1
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
