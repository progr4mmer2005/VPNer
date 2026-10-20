// Package app orchestrates VPNer: configuration, the routing engine, WSL
// connections, the kill switch and the state shown in the UI.
package app

import (
	"vpner/internal/i18n"

	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vpner/internal/bridge"
	"vpner/internal/config"
	"vpner/internal/deps"
	"vpner/internal/engine"
	"vpner/internal/firewall"
	"vpner/internal/providers"
	"vpner/internal/socks5"
	"vpner/internal/winutil"
	"vpner/internal/wslhost"
)

type App struct {
	DataDir string
	Log     *Logger
	// OnAttention is called when a connection needs the user: it asks for
	// input (password, code) or waits for an additional login confirmation.
	OnAttention func(id, name, text string)

	store *config.Store
	ks    *firewall.KillSwitch

	ops sync.Mutex // serialises lifecycle operations

	mu          sync.Mutex
	cfg         *config.Config
	running     bool
	starting    bool
	lastError   string
	setup       *SetupState
	engine      *engine.Mihomo
	tun         *tunnelProc // WireGuard/AmneziaWG tunnels, see tunnels.go
	tunMu       sync.Mutex  // serialises syncTunnels
	wsl         *wslhost.Session
	wslReady    bool
	endpoints   map[string]*endpoint
	vms         map[string]*vmRuntime
	health      map[string]*nativeHealth
	quitAsk     bool // the user asked to quit while VPNs were running
	foreign     []string
	monStop     chan struct{}
	vmEndpoints map[string]engine.LocalEndpoint
	testPorts   map[string]int
	conns       map[string]*connRuntime
	ssoFwd      net.Listener
	// typedPass holds a password the user typed at a prompt; it is saved
	// into the connection once the tunnel comes up with it.
	typedPass map[string]string

	changed chan struct{} // signals UI that the snapshot changed
	subMu   sync.Mutex
	subs    map[chan struct{}]struct{}
}

type SetupState struct {
	Stage string `json:"stage"`
	Done  int64  `json:"done"`
	Total int64  `json:"total"`
}

type connRuntime struct {
	State  string
	Detail string
	IP     string
	DNS    []string
	Since  int64
	Prompt *Prompt
	Want   bool // user wants it connected
}

type Prompt struct {
	Text   string `json:"text"`
	Secret bool   `json:"secret"`
}

type endpoint struct {
	l    net.Listener
	srv  *socks5.Server
	port int
	user string
	pass string
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func New(dataDir string) (*App, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	a := &App{
		DataDir:     dataDir,
		Log:         NewLogger(filepath.Join(dataDir, "logs")),
		store:       &config.Store{Path: filepath.Join(dataDir, "config.json")},
		ks:          &firewall.KillSwitch{StateDir: dataDir},
		endpoints:   map[string]*endpoint{},
		vms:         map[string]*vmRuntime{},
		health:      map[string]*nativeHealth{},
		vmEndpoints: map[string]engine.LocalEndpoint{},
		testPorts:   map[string]int{},
		conns:       map[string]*connRuntime{},
		typedPass:   map[string]string{},
		subs:        map[chan struct{}]struct{}{},
	}
	cfg, err := a.store.Load()
	if err != nil {
		return nil, err
	}
	a.cfg = cfg
	i18n.SetLang(i18n.Resolve(cfg.Settings.Language))
	return a, nil
}

func (a *App) binDir() string                   { return filepath.Join(a.DataDir, "bin") }
func (a *App) cacheDir() string                 { return filepath.Join(a.DataDir, "downloads") }
func (a *App) engineDir() string                { return filepath.Join(a.DataDir, "engine") }
func (a *App) KillSwitch() *firewall.KillSwitch { return a.ks }

// ---- change notification for the UI ----

func (a *App) Subscribe() (chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	a.subMu.Lock()
	a.subs[ch] = struct{}{}
	a.subMu.Unlock()
	return ch, func() {
		a.subMu.Lock()
		delete(a.subs, ch)
		a.subMu.Unlock()
	}
}

func (a *App) notify() {
	a.subMu.Lock()
	defer a.subMu.Unlock()
	for ch := range a.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (a *App) progress(stage string, done, total int64) {
	a.mu.Lock()
	a.setup = &SetupState{Stage: stage, Done: done, Total: total}
	a.mu.Unlock()
	a.notify()
}

func (a *App) clearProgress() {
	a.mu.Lock()
	a.setup = nil
	a.mu.Unlock()
	a.notify()
}

func (a *App) setError(err error) {
	a.mu.Lock()
	if err == nil {
		a.lastError = ""
	} else {
		a.lastError = err.Error()
	}
	a.mu.Unlock()
	if err != nil {
		a.Log.Errorf("app", "%v", err)
	}
	a.notify()
}

// ---- configuration ----

func (a *App) Config() *config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg.Clone()
}

// commit validates, persists and applies a new configuration.
func (a *App) commit(cfg *config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	for i := range cfg.Connections {
		if err := providers.Validate(&cfg.Connections[i]); err != nil {
			return err
		}
	}
	if err := a.store.Save(cfg); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	running := a.running
	a.mu.Unlock()
	a.notify()
	if running {
		return a.applyEngine()
	}
	return nil
}

// SaveConnection creates or updates a connection. Secrets missing from c are
// kept from the stored version (the UI never receives secret values).
func (a *App) SaveConnection(c config.Connection) (string, error) {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	if _, err := providers.Get(c.Type); err != nil {
		return "", err
	}
	if c.Params == nil {
		c.Params = map[string]string{}
	}
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	if c.ID == "" {
		c.ID = config.NewID("c")
		if err := a.provisionAmnezia(&c); err != nil {
			return "", err
		}
		cfg.Connections = append(cfg.Connections, c)
	} else {
		old := cfg.Conn(c.ID)
		if old == nil {
			return "", fmt.Errorf(i18n.T("app.connectionNotFound"), c.ID)
		}
		keyChanged := c.Type == "amnezia-server" && c.Secrets["key"] != "" && c.Secrets["key"] != old.Secrets["key"]
		for k, v := range old.Secrets {
			if _, ok := c.Secrets[k]; !ok {
				c.Secrets[k] = v
			}
		}
		for _, k := range []string{"clientId", "clientIp", "hostKey"} {
			if _, ok := c.Params[k]; !ok && old.Params[k] != "" {
				c.Params[k] = old.Params[k]
			}
		}
		if keyChanged {
			delete(c.Secrets, "config")
			delete(c.Params, "clientId")
			delete(c.Params, "hostKey")
		}
		if err := a.provisionAmnezia(&c); err != nil {
			return "", err
		}
		*old = c
	}
	if err := a.commit(cfg); err != nil {
		return "", err
	}
	a.Log.Infof("app", i18n.T("app.connectionSaved"), c.Name)
	return c.ID, nil
}

func (a *App) DeleteConnection(id string) error {
	a.disconnect(id, false)
	a.removeVM(id)
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	var out []config.Connection
	var name string
	for _, c := range cfg.Connections {
		if c.ID == id {
			name = c.Name
			go a.removeAmneziaClient(c)
			continue
		}
		out = append(out, c)
	}
	cfg.Connections = out
	// Rules that pointed at it must not silently become direct: block instead.
	for i := range cfg.Rules {
		if cfg.Rules[i].Target == id {
			cfg.Rules[i].Target = config.TargetBlock
		}
	}
	if cfg.Settings.FinalTarget == id {
		cfg.Settings.FinalTarget = config.TargetBlock
	}
	// DNS servers that were reached through it are removed together with
	// their rules, so those queries never silently go out directly.
	gone := map[string]bool{}
	var servers []config.DNSServer
	for _, sv := range cfg.DNS.Servers {
		if sv.Via == id {
			gone[sv.ID] = true
			continue
		}
		servers = append(servers, sv)
	}
	if len(gone) > 0 {
		cfg.DNS.Servers = servers
		var rules []config.DNSRule
		for _, r := range cfg.DNS.Rules {
			if !gone[r.Server] {
				rules = append(rules, r)
			}
		}
		cfg.DNS.Rules = rules
		var def []string
		for _, d := range cfg.DNS.Default {
			if !gone[d] {
				def = append(def, d)
			}
		}
		if len(def) == 0 {
			if cfg.DNS.Server(config.DNSSystemID) == nil {
				cfg.DNS.Servers = append(cfg.DNS.Servers, config.DefaultDNS().Servers[0])
			}
			def = []string{config.DNSSystemID}
		}
		cfg.DNS.Default = def
		a.Log.Warnf("app", i18n.T("app.removedDnsServersThatWent"), name)
	}
	a.mu.Lock()
	delete(a.conns, id)
	a.mu.Unlock()
	if err := a.commit(cfg); err != nil {
		return err
	}
	a.Log.Infof("app", i18n.T("app.connectionDeletedRulesThatLed"), name)
	return nil
}

func (a *App) SaveRules(rules []config.Rule) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = config.NewID("r")
		}
	}
	cfg.Rules = rules
	return a.commit(cfg)
}

// SaveDNS replaces the DNS section.
func (a *App) SaveDNS(d config.DNS) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	for i := range d.Servers {
		if d.Servers[i].ID == "" {
			d.Servers[i].ID = config.NewID("dns-")
		}
		d.Servers[i].Address = strings.TrimSpace(d.Servers[i].Address)
	}
	for i := range d.Rules {
		if d.Rules[i].ID == "" {
			d.Rules[i].ID = config.NewID("dr")
		}
	}
	if d.Rules == nil {
		d.Rules = []config.DNSRule{}
	}
	cfg.DNS = d
	return a.commit(cfg)
}

// DNSQuery resolves a name the way the engine would for direct traffic.
func (a *App) DNSQuery(name, qtype string) (any, error) {
	m := a.Engine()
	if m == nil {
		return nil, errors.New(i18n.T("app.turnRoutingOnToCheck"))
	}
	return m.DNSQuery(name, qtype)
}

// SaveAppearance stores the interface look. It changes nothing in routing,
// so the engine is not touched.
func (a *App) SaveAppearance(raw json.RawMessage) error {
	if len(raw) > 256<<10 {
		return errors.New(i18n.T("app.appearanceSettingsAreTooLarge"))
	}
	if !json.Valid(raw) {
		return errors.New(i18n.T("app.appearanceSettingsAreDamaged"))
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	cfg.Appearance = append(json.RawMessage(nil), raw...)
	if err := a.store.Save(cfg); err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.mu.Unlock()
	return nil
}

func (a *App) SaveSettings(s config.Settings) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	prevKS := cfg.Settings.KillSwitch
	prevAuto := cfg.Settings.Autostart
	cfg.Settings = s
	if err := a.commit(cfg); err != nil {
		return err
	}
	i18n.SetLang(i18n.Resolve(s.Language))
	if prevAuto != s.Autostart {
		if err := winutil.SetAutostart(s.Autostart); err != nil {
			return err
		}
	}
	a.mu.Lock()
	running := a.running
	a.mu.Unlock()
	if running && prevKS != s.KillSwitch {
		if s.KillSwitch {
			return a.enableKillSwitch()
		}
		return a.ks.Disable()
	}
	return nil
}

// ---- lifecycle ----

func (a *App) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// Start brings up routing: installs/starts the engine and connects enabled
// connections marked for autostart.
func (a *App) Start() error {
	a.ops.Lock()
	a.mu.Lock()
	if a.running || a.starting {
		a.mu.Unlock()
		a.ops.Unlock()
		return nil
	}
	a.starting = true
	a.mu.Unlock()
	a.notify()
	err := a.startLocked()
	a.mu.Lock()
	a.starting = false
	if err == nil {
		a.running = true
	}
	a.mu.Unlock()
	a.ops.Unlock()
	a.clearProgress()
	a.setError(err)
	if err != nil {
		a.Stop()
		return err
	}
	a.Log.Infof("app", "%s", i18n.T("app.routingIsOn"))
	var ids []string
	for _, c := range a.Config().Connections {
		if c.Enabled && c.Autostart && needsRuntime(c.Type) {
			ids = append(ids, c.ID)
		}
	}
	// One after another: corporate VPNs often confirm logins through the
	// same push service, and two simultaneous requests make one of them
	// fail. The waiting ones are shown as queued, so it is clear they will
	// connect by themselves.
	for _, id := range ids {
		a.setConn(id, func(rt *connRuntime) {
			rt.Want = true
			rt.State, rt.Detail, rt.Prompt = "queued", i18n.T("app.connectsByItselfInTurn"), nil
			rt.Since = time.Now().Unix()
		})
	}
	go func() {
		for k, id := range ids {
			if !a.Running() {
				return
			}
			if !a.isQueued(id) {
				continue // the user connected or cancelled it meanwhile
			}
			a.autoConnect(id)
			wait := fmt.Sprintf(i18n.T("app.connectsByItselfOnceLogin"), a.ConnName(id))
			for _, next := range ids[k+1:] {
				a.setConn(next, func(rt *connRuntime) {
					if rt.State == "queued" {
						rt.Detail = wait
					}
				})
			}
			a.waitLogin(id, 3*time.Minute)
		}
	}()
	return nil
}

func (a *App) autoConnect(id string) {
	if err := a.Connect(id); err != nil {
		a.Log.Errorf(id, i18n.T("app.autoconnect"), err)
	}
}

func (a *App) isQueued(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	rt := a.conns[id]
	return rt != nil && rt.State == "queued" && rt.Want
}

// waitLogin waits while a connection is still logging in (starting, asking
// for input or waiting for a confirmation).
func (a *App) waitLogin(id string, max time.Duration) {
	deadline := time.Now().Add(max)
	time.Sleep(time.Second)
	for time.Now().Before(deadline) && a.Running() {
		a.mu.Lock()
		st := ""
		if rt := a.conns[id]; rt != nil {
			st = rt.State
		}
		a.mu.Unlock()
		if st != "starting" && st != "auth" && st != "confirm" {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func needsRuntime(t string) bool {
	p, err := providers.Get(t)
	return err == nil && p.Runtime() != providers.RuntimeNative
}

func (a *App) startLocked() error {
	bin, err := deps.EnsureMihomo(a.binDir(), a.cacheDir(), a.progress)
	if err != nil {
		return err
	}
	if n := engine.KillStray(bin); n > 0 {
		a.Log.Warnf("app", i18n.T("app.endedHungEngineProcessesLeft"), n)
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	m := &engine.Mihomo{Bin: bin, WorkDir: a.engineDir(), Port: port, Secret: randHex(16),
		Logf: a.engineLog}
	a.mu.Lock()
	a.engine = m
	a.mu.Unlock()
	a.progress(i18n.T("app.startingTunnels"), 0, -1)
	if err := a.syncTunnels(false); err != nil {
		a.Log.Errorf("app", i18n.T("app.tunnelProcessTunnelsWillRun"), err)
	}
	conf, err := a.genConfig()
	if err != nil {
		return err
	}
	a.progress(i18n.T("app.checkingEngineConfiguration"), 0, -1)
	if err := m.Test(conf); err != nil {
		return err
	}
	a.progress(i18n.T("app.startingRoutingEngine"), 0, -1)
	if err := m.Start(conf); err != nil {
		return err
	}
	v, _ := m.Version()
	a.Log.Infof("app", i18n.T("app.mihomoEngineStarted"), v)
	go a.watchEngine(m)
	a.mu.Lock()
	a.monStop = make(chan struct{})
	a.health = map[string]*nativeHealth{}
	stop := a.monStop
	a.mu.Unlock()
	go a.monitor(m, stop)
	if a.Config().Settings.KillSwitch {
		if err := a.enableKillSwitch(); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) enableKillSwitch() error {
	exe, _ := os.Executable()
	a.mu.Lock()
	bin := a.engine.Bin
	a.mu.Unlock()
	if err := a.ks.Enable([]string{exe, bin}, a.Config().Settings.AllowLAN); err != nil {
		return err
	}
	a.Log.Infof("app", "%s", i18n.T("app.systemKillSwitchOnOn"))
	return nil
}

func trimMihomo(line string) string {
	if i := strings.Index(line, "msg="); i >= 0 {
		return strings.Trim(line[i+4:], `"`)
	}
	return line
}

func (a *App) watchEngine(m *engine.Mihomo) {
	<-m.Exited()
	a.mu.Lock()
	cur := a.engine == m && a.running
	a.mu.Unlock()
	if !cur {
		return
	}
	a.Log.Errorf("app", "%s", i18n.T("app.engineExitedUnexpectedlyRestarting"))
	for attempt := 1; ; attempt++ {
		time.Sleep(time.Duration(min(attempt, 10)) * time.Second)
		a.mu.Lock()
		still := a.engine == m && a.running
		a.mu.Unlock()
		if !still {
			return
		}
		conf, err := a.genConfig()
		if err == nil {
			err = m.Start(conf)
		}
		if err == nil {
			a.Log.Infof("app", "%s", i18n.T("app.engineRestarted"))
			go a.watchEngine(m)
			return
		}
		a.Log.Errorf("app", i18n.T("app.restartingEngine"), err)
	}
}

// Stop tears everything down and restores normal networking.
func (a *App) Stop() error {
	a.ops.Lock()
	defer a.ops.Unlock()
	a.mu.Lock()
	wasRunning := a.running
	a.running = false
	m := a.engine
	a.engine = nil
	if a.monStop != nil {
		close(a.monStop)
		a.monStop = nil
	}
	a.foreign = nil
	a.mu.Unlock()

	a.stopAllConns()
	if m != nil {
		m.Stop()
	}
	a.stopTunnels()
	var errs []error
	if a.ks.Active() {
		if err := a.ks.Disable(); err != nil {
			errs = append(errs, err)
		}
	}
	a.closeWSL()
	// Programs may still hold engine (fake) addresses in the DNS cache;
	// without the engine those lead nowhere.
	winutil.FlushDNS()
	if wasRunning {
		a.Log.Infof("app", "%s", i18n.T("app.routingIsOffNetworkIs"))
	}
	a.notify()
	return errors.Join(errs...)
}

// Shutdown is called when the program exits.
func (a *App) Shutdown() { a.Stop() }

// EmergencyRestore removes the kill switch even if state is inconsistent.
func (a *App) EmergencyRestore() error {
	a.Stop()
	return a.ks.Disable()
}

func (a *App) applyEngine() error {
	a.mu.Lock()
	m := a.engine
	running := a.running || a.starting
	a.mu.Unlock()
	if m == nil || !running {
		return nil
	}
	if err := a.syncTunnels(false); err != nil {
		a.Log.Errorf("app", i18n.T("app.tunnelProcess"), err)
	}
	conf, err := a.genConfig()
	if err != nil {
		return err
	}
	if err := m.Test(conf); err != nil {
		return err
	}
	return m.Apply(conf)
}

func loopbackIface() string {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	return ""
}

func (a *App) genConfig() (map[string]any, error) {
	cfg := a.Config()
	a.mu.Lock()
	m := a.engine
	eps := map[string]engine.LocalEndpoint{}
	for id, ep := range a.endpoints {
		eps[id] = engine.LocalEndpoint{Port: ep.port, User: ep.user, Pass: ep.pass}
	}
	for id, ep := range a.vmEndpoints {
		eps[id] = ep
	}
	for id, ep := range a.tunnelEndpointsLocked() {
		eps[id] = ep
	}
	tp := map[string]int{}
	for _, c := range cfg.Connections {
		if !c.Enabled {
			continue
		}
		if _, ok := a.testPorts[c.ID]; !ok {
			if p, err := freePort(); err == nil {
				a.testPorts[c.ID] = p
			}
		}
		tp[c.ID] = a.testPorts[c.ID]
	}
	a.mu.Unlock()
	if m == nil {
		return nil, errors.New(i18n.T("app.engineIsNotRunning"))
	}
	cfg.Settings.LogLevel = "debug" // filtered in engineLog
	exe, _ := os.Executable()
	return engine.Generate(engine.GenInput{
		Cfg: cfg, Endpoints: eps, ControllerPort: m.Port, Secret: m.Secret,
		LoopbackIface: loopbackIface(), TestPorts: tp,
		SelfProcesses: []string{filepath.Base(exe), "mihomo.exe"},
		NoIPv6:        !hasIPv6(),
	})
}

func freePort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---- snapshot for the UI ----

type ConnView struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TypeTitle  string   `json:"typeTitle"`
	Runtime    string   `json:"runtime"`
	Enabled    bool     `json:"enabled"`
	Autostart  bool     `json:"autostart"`
	State      string   `json:"state"`
	Detail     string   `json:"detail,omitempty"`
	IP         string   `json:"ip,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	Since      int64    `json:"since,omitempty"`
	LocalProxy int      `json:"localProxy,omitempty"`
	Prompt     *Prompt  `json:"prompt,omitempty"`
	VMPassword string   `json:"vmPassword,omitempty"`
}

type Snapshot struct {
	Running     bool        `json:"running"`
	Starting    bool        `json:"starting"`
	Error       string      `json:"error,omitempty"`
	Setup       *SetupState `json:"setup,omitempty"`
	KillSwitch  bool        `json:"killSwitch"`
	Connections []ConnView  `json:"connections"`
	// Foreign lists other VPN programs that currently hold the default route.
	Foreign []string `json:"foreign,omitempty"`
	// QuitAsk: the user chose "Выход" while VPNs are on — confirm in the UI.
	QuitAsk bool `json:"quitAsk,omitempty"`
}

func (a *App) Snapshot() Snapshot {
	cfg := a.Config()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{Running: a.running, Starting: a.starting, Error: a.lastError, KillSwitch: a.ks.Active(), Foreign: a.foreign, QuitAsk: a.quitAsk}
	if a.setup != nil {
		st := *a.setup
		s.Setup = &st
	}
	for _, c := range cfg.Connections {
		p, _ := providers.Get(c.Type)
		v := ConnView{ID: c.ID, Name: c.Name, Type: c.Type, Enabled: c.Enabled, Autostart: c.Autostart}
		if p != nil {
			v.TypeTitle = p.Title()
			v.Runtime = string(p.Runtime())
		}
		switch {
		case !c.Enabled:
			v.State = "disabled"
		case p != nil && p.Runtime() == providers.RuntimeNative:
			if a.running {
				v.State, v.Detail = a.nativeStateLocked(c.ID)
			} else {
				v.State = "off"
			}
		default:
			v.State = "off"
			if rt := a.conns[c.ID]; rt != nil {
				v.State, v.Detail, v.IP, v.DNS, v.Since, v.Prompt = rt.State, rt.Detail, rt.IP, rt.DNS, rt.Since, rt.Prompt
			}
		}
		if a.running && c.Enabled {
			v.LocalProxy = a.testPorts[c.ID]
		}
		if v.Runtime == string(providers.RuntimeVM) {
			v.VMPassword = c.Params["consolePassword"]
		}
		s.Connections = append(s.Connections, v)
	}
	return s
}

// ---- helpers for the UI ----

type ProviderView struct {
	Type        string            `json:"type"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Runtime     string            `json:"runtime"`
	Fields      []providers.Field `json:"fields"`
}

func Providers() []ProviderView {
	var out []ProviderView
	for _, p := range providers.All() {
		out = append(out, ProviderView{Type: p.Type(), Title: p.Title(), Description: p.Description(), Runtime: string(p.Runtime()), Fields: p.Fields()})
	}
	return out
}

type IfaceView struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
	Up    bool     `json:"up"`
}

func Interfaces() []IfaceView {
	ifs, _ := net.Interfaces()
	var out []IfaceView
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Name == "VPNer" {
			continue
		}
		v := IfaceView{Name: i.Name, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			v.Addrs = append(v.Addrs, ad.String())
		}
		out = append(out, v)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Name < out[y].Name })
	return out
}

func (a *App) Engine() *engine.Mihomo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.engine
}

// ConnName maps proxy names (connection ids) to display names.
func (a *App) ConnName(id string) string {
	switch id {
	case "DIRECT", "direct-out":
		return i18n.T("app.direct")
	case "REJECT", "REJECT-DROP":
		return i18n.T("app.blocked")
	}
	if c := a.Config().Conn(id); c != nil {
		return c.Name
	}
	return id
}

var _ = bridge.ProtocolVersion

var logRank = map[string]int{"debug": 0, "info": 1, "warning": 2, "error": 3, "fatal": 4}

// engineLog keeps the user's chosen engine log level, plus WireGuard/AmneziaWG
// handshake diagnostics (logged by the engine only at debug level) so that
// stalled tunnels can be explained afterwards.
func (a *App) engineLog(level, line string) {
	want := a.Config().Settings.LogLevel
	if want == "" {
		want = "info"
	}
	if logRank[level] < logRank[want] {
		if !strings.Contains(line, "[WG]") {
			return
		}
		keep := false
		for _, k := range []string{"andshake", "Keypair", "giving up", "rror", "Retrying", "retrying"} {
			if strings.Contains(line, k) {
				keep = true
				break
			}
		}
		if !keep {
			return
		}
	}
	a.Log.Add("engine", level, trimMihomo(line))
}
