//go:build linux

package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"vpner/internal/bridge"
	"vpner/internal/socks5"
)

const runRoot = "/run/vpner"

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

type conn struct {
	a    *Agent
	spec bridge.ProcSpec
	dir  string

	mu     sync.Mutex
	status bridge.ConnStatus
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	// answerHook, when set, receives the next user answer instead of stdin
	// (used for answers that go through a management interface).
	answerHook func(string)
	confirmGen int // invalidates pending "waiting for confirmation" timers
	stopped    bool
	answered   map[int]bool
	answeredAt map[int]time.Time
	// slowRetries counts logins repeated with saved credentials after the
	// server waited for a confirmation that did not come (reset once up).
	slowRetries int

	resolver  *tunnelResolver
	upRe      *regexp.Regexp
	downRe    *regexp.Regexp
	reachRe   *regexp.Regexp
	pendRe    *regexp.Regexp
	reached   bool               // the server has answered during this run
	credsSent bool               // credentials were sent during this run
	pending   *bridge.ConnStatus // hook data waiting for UpPattern
	sawUp     bool               // UpPattern seen since the last (re)start
	uplink    *socks5.Server
	dnsStub   net.PacketConn
	done      chan struct{}
}

// hookState is written next to the connection so hook scripts know options.
type hookState struct {
	RouteAll bool `json:"routeAll"`
}

func (a *Agent) startConn(spec bridge.ProcSpec) error {
	if !idRe.MatchString(spec.ID) {
		return fmt.Errorf("bad connection id %q", spec.ID)
	}
	if len(spec.Argv) == 0 {
		return errors.New("empty argv")
	}
	a.mu.Lock()
	if old, ok := a.conns[spec.ID]; ok {
		a.mu.Unlock()
		old.stop()
		a.mu.Lock()
	}
	c := &conn{a: a, spec: spec, dir: filepath.Join(runRoot, spec.ID), done: make(chan struct{}), answered: map[int]bool{}, answeredAt: map[int]time.Time{}}
	c.status = bridge.ConnStatus{ID: spec.ID, State: "starting", Since: time.Now().Unix()}
	c.resolver = newTunnelResolver(spec.ID, c.dnsServers)
	if spec.UpPattern != "" {
		re, err := regexp.Compile(spec.UpPattern)
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("upPattern: %w", err)
		}
		c.upRe = re
	}
	for _, pp := range []struct {
		pat string
		dst **regexp.Regexp
	}{{spec.ReachedPattern, &c.reachRe}, {spec.PendingPattern, &c.pendRe}} {
		if pp.pat == "" {
			continue
		}
		re, err := regexp.Compile(pp.pat)
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("pattern: %w", err)
		}
		*pp.dst = re
	}
	if spec.DownPattern != "" {
		re, err := regexp.Compile(spec.DownPattern)
		if err != nil {
			a.mu.Unlock()
			return fmt.Errorf("downPattern: %w", err)
		}
		c.downRe = re
	}
	a.conns[spec.ID] = c
	a.mu.Unlock()

	if err := c.prepare(); err != nil {
		c.setState("failed", err.Error())
		c.cleanup()
		return err
	}
	go c.supervise()
	return nil
}

const (
	// A login that fails this long after the credentials went out was held
	// for a confirmation (push) that did not come; a wrong password is
	// rejected at once.
	slowFailure    = 4 * time.Second
	maxSlowRetries = 2
)

// retryAfterSlowFailure decides whether saved credentials may be sent again
// after a login attempt sent at sentAt failed.
func (c *conn) retryAfterSlowFailure(sentAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sentAt.IsZero() || time.Since(sentAt) < slowFailure || c.slowRetries >= maxSlowRetries {
		return false
	}
	c.slowRetries++
	return true
}

func (c *conn) prepare() error {
	os.RemoveAll(c.dir)
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return err
	}
	for name, f := range c.spec.Files {
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			return fmt.Errorf("bad file name %q", name)
		}
		mode := os.FileMode(f.Mode)
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(c.dir, name), []byte(c.expand(f.Content)), mode); err != nil {
			return err
		}
	}
	hs, _ := json.Marshal(hookState{RouteAll: c.spec.RouteAll})
	os.WriteFile(filepath.Join(c.dir, "hook.json"), hs, 0o600)

	if err := createNetns(c.spec.ID); err != nil {
		return err
	}
	// Uplink SOCKS5 and DNS stub live INSIDE the namespace, on its loopback.
	var l net.Listener
	var pc net.PacketConn
	err := inNetns(c.spec.ID, func() error {
		var e error
		if l, e = net.Listen("tcp4", "127.0.0.1:1080"); e != nil {
			return e
		}
		if pc, e = net.ListenPacket("udp4", "127.0.0.1:53"); e != nil {
			l.Close()
			return e
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("uplink listeners: %w", err)
	}
	c.uplink = &socks5.Server{Backend: &hostBackend{a: c.a}, Logf: func(f string, args ...any) {
		c.log(fmt.Sprintf("uplink: "+f, args...))
	}}
	// The daemon talks to the relay from inside its namespace, so the UDP
	// relay socket must live there too (UDP-based VPNs like OpenVPN/udp).
	c.uplink.ListenUDP = func(a *net.UDPAddr) (*net.UDPConn, error) {
		var pc *net.UDPConn
		err := inNetns(c.spec.ID, func() error {
			var e error
			pc, e = net.ListenUDP("udp4", a)
			return e
		})
		return pc, err
	}
	go c.uplink.Serve(l)
	c.dnsStub = pc
	go serveDNSStub(pc, c.a.hostResolve)
	return nil
}

func (c *conn) expand(s string) string {
	r := strings.NewReplacer(
		"{{dir}}", c.dir,
		"{{socks}}", "127.0.0.1:1080",
		"{{socksh}}", "127.0.0.1",
		"{{socksp}}", "1080",
		"{{agent}}", agentPath(),
		"{{id}}", c.spec.ID,
	)
	return r.Replace(s)
}

func (c *conn) supervise() {
	defer close(c.done)
	backoff := 3 * time.Second
	for {
		start := time.Now()
		err := c.runOnce()
		c.mu.Lock()
		stopped := c.stopped
		c.mu.Unlock()
		if stopped {
			c.setState("stopped", "")
			break
		}
		detail := "процесс завершился"
		if err != nil {
			detail = err.Error()
		}
		if !c.spec.Reconnect {
			c.setState("failed", detail)
			break
		}
		if time.Since(start) > time.Minute {
			backoff = 3 * time.Second
		}
		c.setState("down", detail+fmt.Sprintf("; переподключение через %v", backoff))
		select {
		case <-time.After(backoff):
		case <-c.a.quit:
			c.setState("stopped", "")
			c.cleanup()
			return
		}
		if backoff < time.Minute {
			backoff *= 2
		}
		c.mu.Lock()
		stopped = c.stopped
		c.answered = map[int]bool{}
		c.answeredAt = map[int]time.Time{}
		c.mu.Unlock()
		if stopped {
			c.setState("stopped", "")
			break
		}
	}
	c.cleanup()
}

func (c *conn) runOnce() error {
	argv := make([]string, 0, len(c.spec.Argv)+3)
	argv = append(argv, "netns", "exec", nsName(c.spec.ID))
	for _, s := range c.spec.Argv {
		argv = append(argv, c.expand(s))
	}
	cmd := exec.Command("ip", argv...)
	cmd.Dir = c.dir
	cmd.Env = append(os.Environ(), "VPNER_ID="+c.spec.ID, "VPNER_DIR="+c.dir, "VPNER_AGENT="+agentPath())
	for k, v := range c.spec.Env {
		cmd.Env = append(cmd.Env, k+"="+c.expand(v))
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	c.mu.Lock()
	c.cmd = cmd
	c.stdin = stdin
	c.sawUp = false
	c.pending = nil
	c.reached, c.credsSent = false, false
	c.mu.Unlock()
	c.setState("starting", "запущен "+c.spec.Argv[0])
	if c.spec.OpenVPNMgmt {
		go c.runOpenVPNMgmt(cmd)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); c.readOutput(stdout) }()
	go func() { defer wg.Done(); c.readOutput(stderr) }()
	err = cmd.Wait()
	wg.Wait()
	c.mu.Lock()
	c.cmd = nil
	c.stdin = nil
	c.answerHook = nil
	c.mu.Unlock()
	if c.State() == "up" {
		c.setState("down", "туннель закрыт")
	}
	if err != nil {
		return fmt.Errorf("%s: %v", c.spec.Argv[0], err)
	}
	return nil
}

// readOutput turns daemon output into log lines and detects interactive
// prompts (text without a trailing newline that stays idle).
func (c *conn) readOutput(r io.Reader) {
	type chunk struct {
		b   []byte
		err error
	}
	ch := make(chan chunk)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			ch <- chunk{append([]byte(nil), buf[:n]...), err}
			if err != nil {
				return
			}
		}
	}()
	var pending []byte
	timer := time.NewTimer(time.Hour)
	for {
		select {
		case ck := <-ch:
			pending = append(pending, ck.b...)
			for {
				i := indexNL(pending)
				if i < 0 {
					break
				}
				line := strings.TrimRight(string(pending[:i]), "\r")
				pending = pending[i+1:]
				if line != "" {
					c.log(line)
				}
			}
			if ck.err != nil {
				if len(pending) > 0 {
					c.log(string(pending))
				}
				return
			}
			if len(pending) > 0 {
				timer.Reset(400 * time.Millisecond)
			}
		case <-timer.C:
			if len(pending) > 0 {
				p := strings.TrimSpace(string(pending))
				pending = nil
				c.onPrompt(p)
			}
		}
	}
}

func indexNL(b []byte) int {
	for i, x := range b {
		if x == '\n' {
			return i
		}
	}
	return -1
}

var secretPromptRe = regexp.MustCompile(`(?i)pass|pin|otp|token|code|response|secret|парол`)

func (c *conn) onPrompt(p string) {
	c.log(p)
	c.mu.Lock()
	for i, ans := range c.spec.Answers {
		re, err := regexp.Compile(ans.Pattern)
		if err != nil || !re.MatchString(p) {
			continue
		}
		if ans.Once && c.answered[i] {
			sentAt := c.answeredAt[i]
			c.mu.Unlock()
			if !ans.Retry || !c.retryAfterSlowFailure(sentAt) {
				c.mu.Lock()
				continue
			}
			c.log("вход не был подтверждён — повторяю с сохранённым паролем")
			c.mu.Lock()
		}
		c.answered[i] = true
		c.answeredAt[i] = time.Now()
		w := c.stdin
		c.mu.Unlock()
		if w != nil {
			io.WriteString(w, ans.Value+"\n")
		}
		c.afterCredentials()
		return
	}
	c.mu.Unlock()
	c.setState("auth", "ожидается ввод: "+p)
	c.a.emit(bridge.Event{Type: "prompt", ID: c.spec.ID, Prompt: p, Secret: secretPromptRe.MatchString(p)})
}

// afterCredentials notices servers that hold the login until the user
// approves it elsewhere (push notification, bot, etc.): if nothing
// happens a few seconds after credentials were sent, the connection is
// marked as waiting for confirmation and the user is alerted.
func (c *conn) afterCredentials() {
	c.mu.Lock()
	c.confirmGen++
	c.credsSent = true
	gen := c.confirmGen
	c.mu.Unlock()
	time.AfterFunc(5*time.Second, func() {
		c.mu.Lock()
		stale := gen != c.confirmGen || c.stopped
		// Silence only means "waiting for approval" if the server actually
		// answered; otherwise it is a network problem, not a pending login.
		reached := c.reached || c.reachRe == nil
		c.mu.Unlock()
		if stale || !reached || c.State() != "starting" {
			return
		}
		c.markConfirm()
	})
}

const confirmMsg = "ожидает дополнительного подтверждения входа"

func (c *conn) markConfirm() {
	if c.State() == "confirm" {
		return
	}
	c.setState("confirm", confirmMsg)
	c.a.emit(bridge.Event{Type: "attention", ID: c.spec.ID, Prompt: confirmMsg})
}

// askUser shows a prompt in the UI; the answer goes to hook.
func (c *conn) askUser(prompt string, secret bool, hook func(string)) {
	c.mu.Lock()
	c.answerHook = hook
	c.mu.Unlock()
	c.setState("auth", "ожидается ввод: "+prompt)
	c.a.emit(bridge.Event{Type: "prompt", ID: c.spec.ID, Prompt: prompt, Secret: secret})
}

func (c *conn) answer(text string) error {
	c.mu.Lock()
	// The user answered in person: a later failure must not be retried with
	// the saved password in place of what the user typed.
	c.answeredAt = map[int]time.Time{}
	if h := c.answerHook; h != nil {
		c.answerHook = nil
		c.mu.Unlock()
		h(text)
		if c.State() == "auth" {
			c.setState("starting", "ответ отправлен")
		}
		c.afterCredentials()
		return nil
	}
	w := c.stdin
	c.mu.Unlock()
	defer c.afterCredentials()
	if w == nil {
		return errors.New("процесс не запущен")
	}
	_, err := io.WriteString(w, text+"\n")
	if c.State() == "auth" {
		c.setState("starting", "ответ отправлен")
	}
	return err
}

func (c *conn) stop() {
	c.mu.Lock()
	c.stopped = true
	cmd := c.cmd
	c.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case <-c.done:
		case <-time.After(6 * time.Second):
			syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		c.cleanup()
	}
}

func (c *conn) cleanup() {
	if c.uplink != nil {
		c.uplink.Close()
	}
	if c.dnsStub != nil {
		c.dnsStub.Close()
	}
	deleteNetns(c.spec.ID)
	os.RemoveAll(c.dir)
}

func (c *conn) State() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status.State
}

func (c *conn) Status() bridge.ConnStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.status
}

func (c *conn) setState(state, detail string) {
	c.mu.Lock()
	if c.status.State != state {
		c.status.Since = time.Now().Unix()
	}
	c.status.State = state
	c.status.Detail = detail
	if state != "up" {
		c.status.Tun, c.status.IP, c.status.DNS = "", "", nil
	}
	st := c.status
	c.mu.Unlock()
	if state != "up" {
		c.resolver.flush()
	}
	c.a.emit(bridge.Event{Type: "state", ID: c.spec.ID, Status: &st})
}

// reportUp is called by the hook. With an UpPattern the tunnel only counts as
// up once the daemon confirms it in its output.
func (c *conn) reportUp(tun, ip string, dns []string) {
	c.mu.Lock()
	if c.upRe != nil && !c.sawUp {
		c.pending = &bridge.ConnStatus{Tun: tun, IP: ip, DNS: dns}
		c.mu.Unlock()
		c.log("hook: туннель создан, жду подтверждения от " + c.spec.Argv[0])
		return
	}
	c.mu.Unlock()
	c.setUp(tun, ip, dns)
}

func (c *conn) setUp(tun, ip string, dns []string) {
	c.mu.Lock()
	c.slowRetries = 0
	c.status.State = "up"
	c.status.Since = time.Now().Unix()
	c.status.Detail = "туннель поднят"
	c.status.Tun, c.status.IP = tun, ip
	if len(dns) == 0 {
		dns = c.spec.FallbackDNS
	}
	c.status.DNS = dns
	st := c.status
	c.mu.Unlock()
	c.resolver.flush()
	c.a.emit(bridge.Event{Type: "state", ID: c.spec.ID, Status: &st})
}

func (c *conn) dnsServers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.status.DNS...)
}

func (c *conn) log(line string) {
	c.a.emit(bridge.Event{Type: "log", ID: c.spec.ID, Line: line})
	if c.pendRe != nil && c.pendRe.MatchString(line) && c.State() != "up" {
		c.markConfirm()
	}
	if c.reachRe != nil && c.reachRe.MatchString(line) {
		c.mu.Lock()
		first := !c.reached
		c.reached = true
		rearm := first && c.credsSent
		c.mu.Unlock()
		if rearm {
			c.afterCredentials() // credentials went out before the server answered
		}
	}
	if c.downRe != nil && c.downRe.MatchString(line) {
		c.mu.Lock()
		c.sawUp = false
		c.pending = nil
		wasUp := c.status.State == "up"
		c.mu.Unlock()
		if wasUp {
			c.setState("down", "туннель прерван: "+line)
		}
		return
	}
	if c.upRe != nil && c.upRe.MatchString(line) {
		c.mu.Lock()
		c.sawUp = true
		p := c.pending
		c.pending = nil
		c.mu.Unlock()
		if p != nil {
			c.setUp(p.Tun, p.IP, p.DNS)
		}
	}
}

// ---- host-originated traffic into the VPN ----

func (c *conn) ensureUp() error {
	if c.State() != "up" {
		return fmt.Errorf("tunnel %s is not up", c.spec.ID)
	}
	return nil
}

func (c *conn) resolve(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", errors.New("ipv6 is disabled inside VPN namespaces")
		}
		return addr, nil
	}
	ips, err := c.resolver.LookupIPv4(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

// ssoCallbackAddr is the only loopback address inside a namespace the host may
// reach: openconnect's SAML/SSO callback listener. Everything else on the
// namespace loopback (uplink SOCKS, DNS stub) stays private to the daemon.
const ssoCallbackAddr = "127.0.0.1:29786"

func (c *conn) dialTCP(addr string) (net.Conn, error) {
	var ra string
	if addr == ssoCallbackAddr {
		ra = addr
	} else {
		if err := c.ensureUp(); err != nil {
			return nil, err
		}
		var err error
		if ra, err = c.resolve(addr); err != nil {
			return nil, err
		}
		if ip := net.ParseIP(strings.Split(ra, ":")[0]); ip == nil || ip.IsLoopback() {
			return nil, errors.New("loopback destinations are not allowed")
		}
	}
	var nc net.Conn
	err := inNetns(c.spec.ID, func() error {
		var e error
		nc, e = net.DialTimeout("tcp4", ra, 15*time.Second)
		return e
	})
	return nc, err
}

func (c *conn) listenUDP() (*net.UDPConn, error) {
	if err := c.ensureUp(); err != nil {
		return nil, err
	}
	var pc *net.UDPConn
	err := inNetns(c.spec.ID, func() error {
		var e error
		pc, e = net.ListenUDP("udp4", nil)
		return e
	})
	return pc, err
}
