// Package wslhost manages the dedicated WSL distro on the Windows side and the
// bridge session with vpner-agent running inside it.
package wslhost

import (
	"vpner/internal/i18n"

	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"vpner/internal/bridge"
	"vpner/internal/socks5"
)

const (
	DistroName = "vpner"
	AgentPath  = "/opt/vpner/vpner-agent"
)

// Command builds a wsl.exe invocation with UTF-8 output and no console window.
func Command(args ...string) *exec.Cmd {
	cmd := exec.Command("wsl.exe", args...)
	cmd.Env = append(os.Environ(), "WSL_UTF8=1")
	hideWindow(cmd)
	return cmd
}

// Available reports whether WSL2 itself is installed and usable.
func Available() error {
	out, err := Command("--status").CombinedOutput()
	if err != nil {
		return fmt.Errorf(i18n.T("wslhost.wslIsUnavailable"), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Distros() ([]string, error) {
	out, err := Command("-l", "-q").Output()
	if err != nil {
		return nil, err
	}
	var list []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(strings.Trim(l, "\x00\r"))
		if l != "" {
			list = append(list, l)
		}
	}
	return list, nil
}

func DistroExists(name string) bool {
	list, err := Distros()
	if err != nil {
		return false
	}
	for _, d := range list {
		if strings.EqualFold(d, name) {
			return true
		}
	}
	return false
}

func Import(name, installDir, rootfs string) error {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	out, err := Command("--import", name, installDir, rootfs, "--version", "2").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wsl --import: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Unregister(name string) error {
	out, err := Command("--unregister", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wsl --unregister: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func Terminate(name string) { Command("--terminate", name).Run() }

// Run executes a command as root in the distro and returns combined output.
func Run(name string, stdin []byte, argv ...string) (string, error) {
	args := append([]string{"-d", name, "-u", "root", "--exec"}, argv...)
	cmd := Command(args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// WriteFile copies data into the distro through wsl.exe stdin (no /mnt/c
// dependency, works with automount disabled).
func WriteFile(name, path string, data []byte, mode string) error {
	script := fmt.Sprintf("set -e; mkdir -p \"$(dirname '%[1]s')\"; cat > '%[1]s.tmp'; chmod %[2]s '%[1]s.tmp'; mv -f '%[1]s.tmp' '%[1]s'", path, mode)
	_, err := Run(name, data, "/bin/sh", "-c", script)
	return err
}

// ---- agent session ----

// Session is a live bridge to vpner-agent.
type Session struct {
	Distro string
	Logf   func(string)
	// OnEvent receives agent events (state changes, logs, prompts).
	OnEvent func(bridge.Event)
	// OnOpenURL is called when a VPN needs browser-based sign-in.
	OnOpenURL func(conn, url string)
	// Resolve answers the daemons' own DNS lookups (their server names).
	// Defaults to the system resolver.
	Resolve func(ctx context.Context, name string) ([]net.IP, error)
	// Dial is used for the VPN daemons' own traffic to their servers.
	// Defaults to a plain dialer.
	Dial func(network, addr string) (net.Conn, error)

	cmd  *exec.Cmd
	sess *yamux.Session
	done chan struct{}
	err  error
	mu   sync.Mutex
}

func (s *Session) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(fmt.Sprintf(f, a...))
	}
}

// Start launches the agent and establishes the bridge.
func (s *Session) Start() error {
	if s.Dial == nil {
		d := &net.Dialer{Timeout: 20 * time.Second}
		s.Dial = d.Dial
	}
	cmd := Command("-d", s.Distro, "-u", "root", "--exec", "/usr/bin/env", "VPNER_LANG="+i18n.Lang(), AgentPath, "serve")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd
	s.done = make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			s.logf("agent: %s", sc.Text())
		}
	}()
	sess, err := yamux.Client(&rwc{r: stdout, w: stdin, c: cmd}, bridge.YamuxConfig())
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	s.sess = sess
	go func() {
		s.err = cmd.Wait()
		sess.Close()
		close(s.done)
	}()
	go s.acceptLoop()

	var pong map[string]any
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for {
		err = bridge.Call(sess, "ping", nil, &pong)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			s.Close()
			return fmt.Errorf(i18n.T("wslhost.agentDoesNotAnswer"), err)
		case <-s.done:
			return fmt.Errorf(i18n.T("wslhost.agentExited"), s.err)
		case <-time.After(300 * time.Millisecond):
		}
	}
	s.logf(i18n.T("wslhost.wslAgentConnected"), pong)
	go s.eventLoop()
	return nil
}

func (s *Session) Done() <-chan struct{} { return s.done }

func (s *Session) Close() {
	if s.sess != nil {
		bridge.Call(s.sess, "shutdown", nil, nil)
		select {
		case <-s.done:
		case <-time.After(8 * time.Second):
		}
		s.sess.Close()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
}

func (s *Session) Call(method string, params, result any) error {
	if s.sess == nil {
		return errors.New(i18n.T("wslhost.agentIsNotRunning"))
	}
	return bridge.Call(s.sess, method, params, result)
}

func (s *Session) eventLoop() {
	for {
		c, _, err := bridge.Open(s.sess, bridge.Header{Op: bridge.OpEvents})
		if err != nil {
			return
		}
		for {
			var ev bridge.Event
			if err := bridge.ReadJSONLine(c.R, &ev); err != nil {
				break
			}
			if s.OnEvent != nil {
				s.OnEvent(ev)
			}
		}
		c.Close()
		select {
		case <-s.done:
			return
		case <-time.After(time.Second):
		}
	}
}

// acceptLoop serves agent-initiated streams: the VPN daemons' own traffic.
func (s *Session) acceptLoop() {
	for {
		st, err := s.sess.AcceptStream()
		if err != nil {
			return
		}
		go s.handle(st)
	}
}

func (s *Session) handle(st net.Conn) {
	bc := &bridge.BufferedConn{Conn: st, R: bufio.NewReaderSize(st, 32<<10)}
	var h bridge.Header
	st.SetReadDeadline(time.Now().Add(30 * time.Second))
	if err := bridge.ReadJSONLine(bc.R, &h); err != nil {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	fail := func(err error) {
		bridge.WriteJSONLine(bc, bridge.Reply{Error: err.Error()})
		bc.Close()
	}
	switch h.Op {
	case bridge.OpDial:
		up, err := s.Dial("tcp", h.Addr)
		if err != nil {
			s.logf("uplink dial %s: %v", h.Addr, err)
			fail(err)
			return
		}
		if err := bridge.WriteJSONLine(bc, bridge.Reply{OK: true}); err != nil {
			up.Close()
			bc.Close()
			return
		}
		bridge.Pipe(bc, up)
	case bridge.OpUDP:
		s.serveUplinkUDP(bc)
	case bridge.OpResolve:
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var ips []net.IP
		var err error
		if s.Resolve != nil {
			ips, err = s.Resolve(ctx, h.Name)
		} else {
			ips, err = net.DefaultResolver.LookupIP(ctx, "ip4", h.Name)
		}
		cancel()
		if err != nil {
			fail(err)
			return
		}
		r := bridge.Reply{OK: true}
		for _, ip := range ips {
			r.IPs = append(r.IPs, ip.String())
		}
		bridge.WriteJSONLine(bc, r)
		bc.Close()
	case bridge.OpOpenURL:
		bridge.WriteJSONLine(bc, bridge.Reply{OK: true})
		bc.Close()
		if s.OnOpenURL != nil {
			s.OnOpenURL(h.Conn, h.URL)
		}
	default:
		fail(fmt.Errorf("unknown op %q", h.Op))
	}
}

func (s *Session) serveUplinkUDP(bc *bridge.BufferedConn) {
	defer bc.Close()
	pc, err := net.ListenUDP("udp4", nil)
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
	cache := map[string]*net.UDPAddr{}
	for {
		addr, payload, err := bridge.ReadDatagram(bc.R, buf)
		if err != nil {
			return
		}
		ua := cache[addr]
		if ua == nil {
			ua, err = net.ResolveUDPAddr("udp4", addr)
			if err != nil {
				continue
			}
			cache[addr] = ua
		}
		pc.WriteToUDP(payload, ua)
	}
}

// ---- host -> VPN namespace ----

// ConnBackend implements socks5.Backend by forwarding into the namespace of
// one WSL connection.
type ConnBackend struct {
	S    *Session
	Conn string
}

func (b *ConnBackend) DialTCP(addr string) (net.Conn, error) {
	if b.S.sess == nil {
		return nil, errors.New(i18n.T("wslhost.agentIsNotRunning"))
	}
	c, _, err := bridge.Open(b.S.sess, bridge.Header{Op: bridge.OpDial, Conn: b.Conn, Addr: addr})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (b *ConnBackend) OpenUDP() (socks5.UDPSession, error) {
	if b.S.sess == nil {
		return nil, errors.New(i18n.T("wslhost.agentIsNotRunning"))
	}
	c, _, err := bridge.Open(b.S.sess, bridge.Header{Op: bridge.OpUDP, Conn: b.Conn})
	if err != nil {
		return nil, err
	}
	return &streamUDP{c: c}, nil
}

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

type rwc struct {
	r io.Reader
	w io.WriteCloser
	c *exec.Cmd
}

func (x *rwc) Read(p []byte) (int, error)  { return x.r.Read(p) }
func (x *rwc) Write(p []byte) (int, error) { return x.w.Write(p) }
func (x *rwc) Close() error                { return x.w.Close() }
