//go:build linux

// Package agent is the Linux side of VPNer. It runs inside the dedicated WSL
// distro, talks to vpner.exe over a yamux session on stdio, and hosts each VPN
// daemon in its own sealed network namespace.
package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"vpner/internal/bridge"
	"vpner/internal/socks5"
)

const Version = "0.1.0"

type Agent struct {
	sess *yamux.Session

	mu    sync.Mutex
	conns map[string]*conn

	subMu sync.Mutex
	subs  map[*bridge.BufferedConn]chan bridge.Event

	quit     chan struct{}
	quitOnce sync.Once
}

func agentPath() string {
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "/opt/vpner/vpner-agent"
}

type stdio struct{}

func (stdio) Read(p []byte) (int, error)  { return os.Stdin.Read(p) }
func (stdio) Write(p []byte) (int, error) { return os.Stdout.Write(p) }
func (stdio) Close() error                { os.Stdin.Close(); return os.Stdout.Close() }

// Serve runs the agent over stdin/stdout until the host goes away.
func Serve() error {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	os.MkdirAll(runRoot, 0o700)
	cleanupStaleNetns()

	sess, err := yamux.Server(stdio{}, bridge.YamuxConfig())
	if err != nil {
		return err
	}
	a := &Agent{sess: sess, conns: map[string]*conn{}, subs: map[*bridge.BufferedConn]chan bridge.Event{}, quit: make(chan struct{})}
	go a.serveHooks()
	go a.serveSetupProxy()
	log.Printf("vpner-agent %s ready", Version)
	for {
		st, err := sess.AcceptStream()
		if err != nil {
			break
		}
		go a.handleStream(st)
	}
	log.Printf("host disconnected, shutting down")
	a.shutdown()
	return nil
}

func (a *Agent) shutdown() {
	a.quitOnce.Do(func() { close(a.quit) })
	a.mu.Lock()
	list := make([]*conn, 0, len(a.conns))
	for _, c := range a.conns {
		list = append(list, c)
	}
	a.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range list {
		wg.Add(1)
		go func(c *conn) { defer wg.Done(); c.stop() }(c)
	}
	wg.Wait()
	cleanupStaleNetns()
}

func (a *Agent) handleStream(st net.Conn) {
	bc := &bridge.BufferedConn{Conn: st, R: bufio.NewReaderSize(st, 32<<10)}
	var h bridge.Header
	st.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := bridge.ReadJSONLine(bc.R, &h); err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	switch h.Op {
	case bridge.OpRPC:
		a.handleRPC(bc)
	case bridge.OpEvents:
		a.handleEvents(bc)
	case bridge.OpDial:
		a.handleDial(bc, h)
	case bridge.OpUDP:
		a.handleUDP(bc, h)
	default:
		bridge.WriteJSONLine(st, bridge.Reply{Error: "unknown op " + h.Op})
		st.Close()
	}
}

// ---- events ----

func (a *Agent) emit(ev bridge.Event) {
	ev.Time = time.Now().UnixMilli()
	a.subMu.Lock()
	defer a.subMu.Unlock()
	for _, ch := range a.subs {
		select {
		case ch <- ev:
		default: // slow consumer: drop rather than block VPN handling
		}
	}
}

func (a *Agent) handleEvents(bc *bridge.BufferedConn) {
	ch := make(chan bridge.Event, 1024)
	a.subMu.Lock()
	a.subs[bc] = ch
	a.subMu.Unlock()
	defer func() {
		a.subMu.Lock()
		delete(a.subs, bc)
		a.subMu.Unlock()
		bc.Close()
	}()
	// initial snapshot
	for _, s := range a.statuses() {
		s := s
		if err := bridge.WriteJSONLine(bc, bridge.Event{Type: "state", ID: s.ID, Status: &s, Time: time.Now().UnixMilli()}); err != nil {
			return
		}
	}
	for {
		select {
		case ev := <-ch:
			if err := bridge.WriteJSONLine(bc, ev); err != nil {
				return
			}
		case <-a.quit:
			return
		}
	}
}

func (a *Agent) statuses() []bridge.ConnStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]bridge.ConnStatus, 0, len(a.conns))
	for _, c := range a.conns {
		out = append(out, c.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (a *Agent) get(id string) (*conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.conns[id]
	if !ok {
		return nil, fmt.Errorf("unknown connection %q", id)
	}
	return c, nil
}

// ---- RPC ----

func (a *Agent) handleRPC(bc *bridge.BufferedConn) {
	defer bc.Close()
	var req bridge.Request
	if err := bridge.ReadJSONLine(bc.R, &req); err != nil {
		return
	}
	res, err := a.dispatch(req)
	resp := bridge.Response{}
	if err != nil {
		resp.Error = err.Error()
	} else if res != nil {
		b, _ := json.Marshal(res)
		resp.Result = b
	}
	bridge.WriteJSONLine(bc, resp)
}

func (a *Agent) dispatch(req bridge.Request) (any, error) {
	switch req.Method {
	case "ping":
		return map[string]any{"version": Version, "protocol": bridge.ProtocolVersion}, nil
	case "exec":
		var p bridge.ExecParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, err
		}
		return execCmd(p)
	case "conn.start":
		var p bridge.ProcSpec
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, err
		}
		return nil, a.startConn(p)
	case "conn.stop":
		var p struct{ ID string }
		json.Unmarshal(req.Params, &p)
		c, err := a.get(p.ID)
		if err != nil {
			return nil, nil
		}
		c.stop()
		a.mu.Lock()
		if a.conns[p.ID] == c {
			delete(a.conns, p.ID)
		}
		a.mu.Unlock()
		return nil, nil
	case "conn.answer":
		var p bridge.AnswerParams
		json.Unmarshal(req.Params, &p)
		c, err := a.get(p.ID)
		if err != nil {
			return nil, err
		}
		return nil, c.answer(p.Text)
	case "conn.list":
		return a.statuses(), nil
	case "shutdown":
		go func() {
			a.shutdown()
			a.sess.Close()
		}()
		return nil, nil
	}
	return nil, fmt.Errorf("unknown method %q", req.Method)
}

func execCmd(p bridge.ExecParams) (*bridge.ExecResult, error) {
	if len(p.Argv) == 0 {
		return nil, errors.New("empty argv")
	}
	cmd := exec.Command(p.Argv[0], p.Argv[1:]...)
	cmd.Env = os.Environ()
	for k, v := range p.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if p.Stdin != "" {
		cmd.Stdin = strings.NewReader(p.Stdin)
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// Background children (daemons) may keep the output pipe open; do not
	// wait for them once the command itself has exited.
	cmd.WaitDelay = 3 * time.Second
	err := cmd.Run()
	res := &bridge.ExecResult{Output: out.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Code = ee.ExitCode()
		} else if errors.Is(err, exec.ErrWaitDelay) {
			res.Code = 0
		} else {
			return nil, err
		}
	}
	return res, nil
}

// ---- host -> VPN traffic ----

func (a *Agent) handleDial(bc *bridge.BufferedConn, h bridge.Header) {
	c, err := a.get(h.Conn)
	if err != nil {
		bridge.WriteJSONLine(bc, bridge.Reply{Error: err.Error()})
		bc.Close()
		return
	}
	nc, err := c.dialTCP(h.Addr)
	if err != nil {
		bridge.WriteJSONLine(bc, bridge.Reply{Error: err.Error()})
		bc.Close()
		return
	}
	if err := bridge.WriteJSONLine(bc, bridge.Reply{OK: true}); err != nil {
		nc.Close()
		bc.Close()
		return
	}
	bridge.Pipe(bc, nc)
}

func (a *Agent) handleUDP(bc *bridge.BufferedConn, h bridge.Header) {
	defer bc.Close()
	c, err := a.get(h.Conn)
	if err != nil {
		bridge.WriteJSONLine(bc, bridge.Reply{Error: err.Error()})
		return
	}
	pc, err := c.listenUDP()
	if err != nil {
		bridge.WriteJSONLine(bc, bridge.Reply{Error: err.Error()})
		return
	}
	defer pc.Close()
	if err := bridge.WriteJSONLine(bc, bridge.Reply{OK: true}); err != nil {
		return
	}
	var wmu sync.Mutex
	go func() {
		buf := make([]byte, bridge.MaxDatagram)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				bc.Close()
				return
			}
			wmu.Lock()
			err = bridge.WriteDatagram(bc, from.String(), buf[:n])
			wmu.Unlock()
			if err != nil {
				pc.Close()
				return
			}
		}
	}()
	buf := make([]byte, bridge.MaxDatagram)
	for {
		addr, payload, err := bridge.ReadDatagram(bc.R, buf)
		if err != nil {
			return
		}
		ra, err := c.resolve(addr)
		if err != nil {
			continue
		}
		ua, err := net.ResolveUDPAddr("udp4", ra)
		if err != nil || ua.IP.IsLoopback() {
			continue
		}
		pc.WriteToUDP(payload, ua)
	}
}

// ---- VPN daemon -> host (uplink) ----

type hostBackend struct{ a *Agent }

func (b *hostBackend) DialTCP(addr string) (net.Conn, error) {
	c, _, err := bridge.Open(b.a.sess, bridge.Header{Op: bridge.OpDial, Addr: addr})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (b *hostBackend) OpenUDP() (socks5.UDPSession, error) {
	c, _, err := bridge.Open(b.a.sess, bridge.Header{Op: bridge.OpUDP})
	if err != nil {
		return nil, err
	}
	return &streamUDP{c: c}, nil
}

// streamUDP carries datagrams over a bridge stream.
type streamUDP struct {
	c  *bridge.BufferedConn
	mu sync.Mutex
}

func (s *streamUDP) Send(addr string, p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bridge.WriteDatagram(s.c, addr, p)
}

func (s *streamUDP) Recv(buf []byte) (string, []byte, error) { return bridge.ReadDatagram(s.c.R, buf) }
func (s *streamUDP) Close() error                            { return s.c.Close() }

func (a *Agent) hostResolve(name string) ([]net.IP, error) {
	c, r, err := bridge.Open(a.sess, bridge.Header{Op: bridge.OpResolve, Name: name})
	if err != nil {
		return nil, err
	}
	c.Close()
	var ips []net.IP
	for _, s := range r.IPs {
		if ip := net.ParseIP(s); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// serveSetupProxy offers an HTTP proxy on loopback of the distro's root
// namespace, used only by package installation (apk). All its traffic goes
// through the host, so setup works even when WSL networking is blocked.
func (a *Agent) serveSetupProxy() {
	l, err := net.Listen("tcp4", "127.0.0.1:3128")
	if err != nil {
		log.Printf("setup proxy: %v", err)
		return
	}
	backend := &hostBackend{a: a}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			up, err := backend.DialTCP(r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				up.Close()
				return
			}
			cl, brw, err := hj.Hijack()
			if err != nil {
				up.Close()
				return
			}
			cl.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			var client io.ReadWriteCloser = cl
			if brw.Reader.Buffered() > 0 {
				client = &bridge.BufferedConn{Conn: cl, R: brw.Reader}
			}
			bridge.Pipe(client, up)
			return
		}
		if r.URL.Host == "" {
			http.Error(w, "proxy only", http.StatusBadRequest)
			return
		}
		tr := &http.Transport{DialContext: nil, Dial: func(network, addr string) (net.Conn, error) { return backend.DialTCP(addr) }}
		r.RequestURI = ""
		resp, err := tr.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	})}
	srv.Serve(l)
}
