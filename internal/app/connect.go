package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"vpner/internal/bridge"
	"vpner/internal/deps"
	"vpner/internal/providers"
	"vpner/internal/socks5"
	"vpner/internal/wslhost"
)

// Connect starts a connection that needs a runtime (WSL namespace or VM).
func (a *App) Connect(id string) error {
	if !a.Running() {
		if err := a.Start(); err != nil {
			return err
		}
	}
	cfg := a.Config()
	c := cfg.Conn(id)
	if c == nil {
		return fmt.Errorf("подключение %s не найдено", id)
	}
	if !c.Enabled {
		return fmt.Errorf("подключение «%s» выключено", c.Name)
	}
	p, err := providers.Get(c.Type)
	if err != nil {
		return err
	}
	switch pp := p.(type) {
	case providers.WSLProvider:
		return a.connectWSL(c.ID, c.Name, pp)
	case VMRuntime:
		return a.connectVM(c.ID, pp)
	case providers.NativeProvider:
		return nil // always available while routing is on
	}
	return fmt.Errorf("тип %s не поддерживает подключение", c.Type)
}

func (a *App) setConn(id string, f func(rt *connRuntime)) {
	a.mu.Lock()
	rt := a.conns[id]
	if rt == nil {
		rt = &connRuntime{State: "off"}
		a.conns[id] = rt
	}
	f(rt)
	a.mu.Unlock()
	a.notify()
}

func (a *App) connectWSL(id, name string, p providers.WSLProvider) error {
	a.setConn(id, func(rt *connRuntime) {
		rt.Want = true
		rt.State, rt.Detail, rt.Prompt = "starting", "подготовка контейнера", nil
		rt.Since = time.Now().Unix()
	})
	fail := func(err error) error {
		a.setConn(id, func(rt *connRuntime) { rt.State, rt.Detail, rt.Want = "failed", err.Error(), false })
		a.Log.Errorf(id, "%v", err)
		return err
	}
	s, err := a.ensureWSL()
	if err != nil {
		return fail(err)
	}
	if err := deps.EnsurePackages(s, providers.AllPackages(), a.progress); err != nil {
		a.clearProgress()
		return fail(err)
	}
	a.clearProgress()
	c := a.Config().Conn(id)
	if c == nil {
		return fail(errors.New("подключение удалено"))
	}
	spec, err := p.Spec(c)
	if err != nil {
		return fail(err)
	}
	if err := a.ensureEndpoint(id, &wslBackend{a: a, id: id}); err != nil {
		return fail(err)
	}
	if err := s.Call("conn.start", spec, nil); err != nil {
		return fail(err)
	}
	a.Log.Infof(id, "запуск «%s» в изолированном контейнере", name)
	return a.applyEngine()
}

// Disconnect stops a runtime connection. Rules pointing at it start rejecting
// traffic (fail closed) until it is connected again.
func (a *App) Disconnect(id string) error { return a.disconnect(id, true) }

func (a *App) disconnect(id string, apply bool) error {
	a.mu.Lock()
	s := a.wsl
	rt := a.conns[id]
	if rt != nil {
		rt.Want = false
	}
	a.mu.Unlock()
	if s != nil {
		s.Call("conn.stop", map[string]string{"ID": id}, nil)
	}
	a.stopVM(id)
	a.closeEndpoint(id)
	a.setConn(id, func(rt *connRuntime) {
		rt.State, rt.Detail, rt.Prompt, rt.IP, rt.DNS = "off", "", nil, "", nil
	})
	if apply {
		return a.applyEngine()
	}
	return nil
}

func (a *App) stopAllConns() {
	a.mu.Lock()
	var ids []string
	for id := range a.conns {
		ids = append(ids, id)
	}
	a.mu.Unlock()
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id string) { defer wg.Done(); a.disconnect(id, false) }(id)
	}
	wg.Wait()
}

// Answer sends user input (password, OTP, yes/no) to a waiting VPN daemon.
func (a *App) Answer(id, text string) error {
	a.mu.Lock()
	s := a.wsl
	a.mu.Unlock()
	if s == nil {
		return errors.New("контейнер не запущен")
	}
	a.setConn(id, func(rt *connRuntime) {
		if rt.Prompt != nil && rt.Prompt.Secret && passwordPromptRe.MatchString(strings.TrimSpace(rt.Prompt.Text)) {
			a.typedPass[id] = text
		}
		rt.Prompt = nil
	})
	return s.Call("conn.answer", bridge.AnswerParams{ID: id, Text: text}, nil)
}

// passwordPromptRe matches prompts for the account password (not one-time
// codes or key passphrases), whose answer is worth remembering.
var passwordPromptRe = regexp.MustCompile(`(?i)^(password|пароль openvpn)\s*:?$`)

// rememberPassword saves a password the user typed once it has worked, so
// the next login does not ask again.
func (a *App) rememberPassword(id, pw string) {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	c := cfg.Conn(id)
	if c == nil || c.S("password") == pw {
		return
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	c.Secrets["password"] = pw
	if err := a.store.Save(cfg); err != nil {
		a.Log.Errorf(id, "не удалось сохранить пароль: %v", err)
		return
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	a.Log.Infof(id, "введённый пароль подошёл и сохранён — в следующий раз он подставится сам")
}

// ---- local SOCKS endpoints (mihomo -> vpner -> namespace) ----

func (a *App) ensureEndpoint(id string, backend socks5.Backend) error {
	a.mu.Lock()
	if _, ok := a.endpoints[id]; ok {
		a.mu.Unlock()
		return nil
	}
	a.mu.Unlock()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	ep := &endpoint{l: l, port: l.Addr().(*net.TCPAddr).Port, user: randHex(6), pass: randHex(16)}
	ep.srv = &socks5.Server{Backend: backend, User: ep.user, Pass: ep.pass, Logf: func(f string, args ...any) {
		a.Log.Add(id, "debug", fmt.Sprintf(f, args...))
	}}
	go ep.srv.Serve(l)
	a.mu.Lock()
	a.endpoints[id] = ep
	a.mu.Unlock()
	return nil
}

func (a *App) closeEndpoint(id string) {
	a.mu.Lock()
	ep := a.endpoints[id]
	delete(a.endpoints, id)
	a.mu.Unlock()
	if ep != nil {
		ep.srv.Close()
	}
}

type wslBackend struct {
	a  *App
	id string
}

func (b *wslBackend) session() (*wslhost.Session, error) {
	b.a.mu.Lock()
	s := b.a.wsl
	b.a.mu.Unlock()
	if s == nil {
		return nil, errors.New("контейнер WSL не запущен")
	}
	return s, nil
}

func (b *wslBackend) DialTCP(addr string) (net.Conn, error) {
	s, err := b.session()
	if err != nil {
		return nil, err
	}
	return (&wslhost.ConnBackend{S: s, Conn: b.id}).DialTCP(addr)
}

func (b *wslBackend) OpenUDP() (socks5.UDPSession, error) {
	s, err := b.session()
	if err != nil {
		return nil, err
	}
	return (&wslhost.ConnBackend{S: s, Conn: b.id}).OpenUDP()
}

// ---- WSL session ----

func (a *App) ensureWSL() (*wslhost.Session, error) {
	a.mu.Lock()
	if a.wsl != nil && a.wslReady {
		s := a.wsl
		a.mu.Unlock()
		return s, nil
	}
	a.mu.Unlock()

	a.ops.Lock()
	defer a.ops.Unlock()
	a.mu.Lock()
	if a.wsl != nil && a.wslReady {
		s := a.wsl
		a.mu.Unlock()
		return s, nil
	}
	a.mu.Unlock()

	if err := deps.EnsureDistro(a.DataDir, a.cacheDir(), a.progress); err != nil {
		a.clearProgress()
		return nil, err
	}
	a.progress("Запуск агента в контейнере", 0, -1)
	s := &wslhost.Session{
		Distro:    wslhost.DistroName,
		Logf:      func(l string) { a.Log.Add("agent", "info", l) },
		OnEvent:   a.onAgentEvent,
		OnOpenURL: a.onOpenURL,
		Resolve:   a.resolveServerName,
	}
	if err := s.Start(); err != nil {
		a.clearProgress()
		return nil, err
	}
	a.mu.Lock()
	a.wsl = s
	a.wslReady = true
	a.mu.Unlock()
	go a.watchWSL(s)
	return s, nil
}

func (a *App) watchWSL(s *wslhost.Session) {
	<-s.Done()
	a.mu.Lock()
	if a.wsl != s {
		a.mu.Unlock()
		return
	}
	a.wsl = nil
	a.wslReady = false
	var want []string
	for id, rt := range a.conns {
		if rt.Want {
			want = append(want, id)
			rt.State, rt.Detail = "down", "контейнер WSL перезапускается"
		}
	}
	running := a.running
	a.mu.Unlock()
	a.notify()
	if !running {
		return
	}
	a.Log.Errorf("app", "агент WSL отключился — перезапуск")
	time.Sleep(3 * time.Second)
	for _, id := range want {
		if err := a.Connect(id); err != nil {
			a.Log.Errorf(id, "переподключение: %v", err)
		}
	}
}

func (a *App) closeWSL() {
	a.mu.Lock()
	s := a.wsl
	a.wsl = nil
	a.wslReady = false
	a.mu.Unlock()
	if s != nil {
		s.Close()
	}
}

func (a *App) onAgentEvent(ev bridge.Event) {
	switch ev.Type {
	case "log":
		a.Log.Add(ev.ID, "info", ev.Line)
	case "state":
		st := ev.Status
		a.setConn(ev.ID, func(rt *connRuntime) {
			rt.State, rt.Detail, rt.IP, rt.DNS, rt.Since = st.State, st.Detail, st.IP, st.DNS, st.Since
			if st.State != "auth" {
				rt.Prompt = nil
			}
		})
		if st.State == "up" {
			a.Log.Infof(ev.ID, "туннель поднят: адрес %s, DNS %v", st.IP, st.DNS)
			a.mu.Lock()
			pw := a.typedPass[ev.ID]
			delete(a.typedPass, ev.ID)
			a.mu.Unlock()
			if pw != "" {
				go a.rememberPassword(ev.ID, pw)
			}
		}
	case "prompt":
		a.setConn(ev.ID, func(rt *connRuntime) {
			rt.Prompt = &Prompt{Text: ev.Prompt, Secret: ev.Secret}
			rt.State = "auth"
		})
		a.Log.Infof(ev.ID, "ожидается ввод: %s", ev.Prompt)
		if a.OnAttention != nil {
			go a.OnAttention(ev.ID, a.ConnName(ev.ID), "запрашивает ввод: "+ev.Prompt)
		}
	case "attention":
		a.Log.Infof(ev.ID, "%s", ev.Prompt)
		if a.OnAttention != nil {
			go a.OnAttention(ev.ID, a.ConnName(ev.ID), ev.Prompt)
		}
	}
}

// ---- browser sign-in (SAML/SSO) ----

const ssoPort = "127.0.0.1:29786"

func (a *App) onOpenURL(conn, url string) {
	a.Log.Infof(conn, "вход через браузер: %s", url)
	a.startSSOForwarder(conn)
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		a.Log.Errorf(conn, "не удалось открыть браузер: %v — откройте ссылку вручную", err)
	}
}

// startSSOForwarder exposes the SSO callback port of a namespace on Windows
// localhost for a few minutes, so the browser can hand the login token back.
func (a *App) startSSOForwarder(conn string) {
	a.mu.Lock()
	if a.ssoFwd != nil {
		a.ssoFwd.Close()
	}
	l, err := net.Listen("tcp4", ssoPort)
	if err != nil {
		a.mu.Unlock()
		a.Log.Errorf(conn, "порт входа %s занят: %v", ssoPort, err)
		return
	}
	a.ssoFwd = l
	a.mu.Unlock()
	go func() {
		time.AfterFunc(10*time.Minute, func() { l.Close() })
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				up, err := (&wslBackend{a: a, id: conn}).DialTCP(ssoPort)
				if err != nil {
					c.Close()
					return
				}
				bridge.Pipe(c, up)
			}()
		}
	}()
}

// resolveServerName resolves VPN server names for the daemons. With the
// engine running, system DNS would return FakeIP addresses (198.18.x), so
// the engine's own resolver is asked for the real ones.
func (a *App) resolveServerName(ctx context.Context, name string) ([]net.IP, error) {
	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}
	if m := a.Engine(); m != nil {
		if res, err := m.DNSQuery(name, "A"); err == nil {
			var ips []net.IP
			if ans, ok := res["Answer"].([]any); ok {
				for _, x := range ans {
					rec, _ := x.(map[string]any)
					if ip := net.ParseIP(fmt.Sprint(rec["data"])); ip != nil && ip.To4() != nil {
						ips = append(ips, ip)
					}
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
		}
	}
	return net.DefaultResolver.LookupIP(ctx, "ip4", name)
}
