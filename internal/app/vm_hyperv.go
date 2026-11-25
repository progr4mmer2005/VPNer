package app

import (
	"vpner/internal/i18n"

	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"vpner/internal/assets"
	"vpner/internal/config"
	"vpner/internal/engine"
	"vpner/internal/hyperv"
	"vpner/internal/providers"
)

type vmRuntime struct {
	name string
	ip   string
	user string
	pass string
	stop chan struct{}
}

func (a *App) vmDir(id string) string { return filepath.Join(a.DataDir, "vms", id) }

// ensureVMIdentity allocates the LAN address, MACs and passwords of a VM
// connection once and stores them with the connection.
func (a *App) ensureVMIdentity(id string) (*config.Connection, error) {
	cfg := a.Config()
	c := cfg.Conn(id)
	if c == nil {
		return nil, fmt.Errorf(i18n.T("app.connectionNotFound"), id)
	}
	if c.P("lanIp") != "" && c.P("wanMac") != "" && c.S("gwPass") != "" {
		return c, nil
	}
	used := map[string]bool{}
	for _, o := range cfg.Connections {
		if ip := o.P("lanIp"); ip != "" {
			used[ip] = true
		}
	}
	nc := *c
	nc.Params = map[string]string{}
	for k, v := range c.Params {
		nc.Params[k] = v
	}
	nc.Secrets = map[string]string{}
	for k, v := range c.Secrets {
		nc.Secrets[k] = v
	}
	if nc.Params["lanIp"] == "" {
		for n := 10; n < 250; n++ {
			ip := hyperv.LANPrefix + strconv.Itoa(n)
			if !used[ip] {
				nc.Params["lanIp"] = ip
				break
			}
		}
		if nc.Params["lanIp"] == "" {
			return nil, errors.New(i18n.T("app.noAddressesLeftForVirtual"))
		}
	}
	if nc.Params["wanMac"] == "" {
		nc.Params["wanMac"] = hyperv.NewMAC()
		nc.Params["lanMac"] = hyperv.NewMAC()
	}
	if nc.Params["consolePassword"] == "" {
		nc.Params["consolePassword"] = randHex(5)
	}
	if nc.Secrets["gwPass"] == "" {
		nc.Secrets["gwPass"] = randHex(16)
	}
	if _, err := a.SaveConnection(nc); err != nil {
		return nil, err
	}
	return a.Config().Conn(id), nil
}

func (a *App) vmConnect(id string, p VMRuntime) error {
	a.setConn(id, func(rt *connRuntime) {
		rt.Want = true
		rt.State, rt.Detail, rt.Prompt = "starting", i18n.T("app.preparingVirtualMachine"), nil
		rt.Since = time.Now().Unix()
	})
	fail := func(err error) error {
		a.clearProgress()
		a.setConn(id, func(rt *connRuntime) { rt.State, rt.Detail, rt.Want = "failed", err.Error(), false })
		a.Log.Errorf(id, "%v", err)
		return err
	}
	if err := hyperv.Available(); err != nil {
		return fail(err)
	}
	c, err := a.ensureVMIdentity(id)
	if err != nil {
		return fail(err)
	}
	spec, err := p.VM(c)
	if err != nil {
		return fail(err)
	}
	a.progress(i18n.T("app.settingUpHyperVNetwork"), 0, -1)
	if err := hyperv.EnsureLAN(); err != nil {
		return fail(err)
	}
	if !hyperv.Exists(spec.VMName) {
		wan, err := hyperv.EnsureWAN(func(s string) { a.Log.Infof(id, "%s", s) })
		if err != nil {
			return fail(err)
		}
		base, err := hyperv.EnsureBaseImage(a.cacheDir(), filepath.Join(a.DataDir, "images"), a.progress)
		if err != nil {
			return fail(err)
		}
		agent, _, err := assets.Agent("")
		if err != nil {
			return fail(err)
		}
		dir := a.vmDir(id)
		seed := filepath.Join(dir, "seed-src")
		err = hyperv.WriteSeed(seed, hyperv.SeedConfig{
			ID: id + "-" + randHex(3), Hostname: vmHostname(id, spec), LANIP: c.P("lanIp"),
			WANMac: hyperv.MACColon(c.P("wanMac")), LANMac: hyperv.MACColon(c.P("lanMac")),
			GatewayUser: "vpner", GatewayPass: c.S("gwPass"), ConsolePass: c.P("consolePassword"),
			Desktop: spec.Desktop, FallbackDNS: spec.DNS, Agent: agent, App: spec.App,
		})
		if err != nil {
			return fail(err)
		}
		a.progress(fmt.Sprintf(i18n.T("app.creatingVirtualMachine"), c.Name), 0, -1)
		a.Log.Infof(id, i18n.T("app.creatingVirtualMachineMbCpu"), spec.VMName, spec.MemoryMB, spec.CPUs, spec.DiskGB, wan)
		err = hyperv.Create(base, hyperv.VMConfig{Name: spec.VMName, Dir: dir, MemoryMB: spec.MemoryMB, CPUs: spec.CPUs,
			DiskGB: spec.DiskGB, WAN: wan, WANMac: c.P("wanMac"), LANMac: c.P("lanMac"), SeedDir: seed})
		os.RemoveAll(seed)
		if err != nil {
			return fail(err)
		}
		// Remember what was set up in this VM: the app is installed only
		// when the VM is created.
		os.Remove(filepath.Join(dir, vmSubSent))
		os.Remove(filepath.Join(dir, vmSetUpFile))
		os.WriteFile(filepath.Join(dir, vmCreatedFile), []byte(strconv.FormatInt(time.Now().Unix(), 10)), 0o644)
		if spec.App != "" {
			if err := os.WriteFile(filepath.Join(dir, vmAppFile), []byte(spec.App), 0o644); err != nil {
				a.Log.Warnf(id, "%v", err)
			}
		}
	}
	a.clearProgress()
	if st, _ := hyperv.State(spec.VMName); st != "Running" {
		if err := hyperv.Start(spec.VMName); err != nil {
			return fail(fmt.Errorf(i18n.T("app.startingVm"), err))
		}
	}
	rt := &vmRuntime{name: spec.VMName, ip: c.P("lanIp"), user: "vpner", pass: c.S("gwPass"), stop: make(chan struct{})}
	a.mu.Lock()
	if old := a.vms[id]; old != nil {
		close(old.stop)
	}
	a.vms[id] = rt
	delete(a.vmHealth, id) // connected anew: the restart count starts over
	a.vmEndpoints[id] = engine.LocalEndpoint{Server: rt.ip, Port: 1080, User: rt.user, Pass: rt.pass, Iface: hyperv.LANAlias}
	a.mu.Unlock()
	a.setConn(id, func(r *connRuntime) { r.State, r.Detail = "provisioning", i18n.T("app.virtualMachineIsStarting") })
	a.Log.Infof(id, i18n.T("app.virtualMachineIsRunningGateway"), spec.VMName, rt.ip)
	go a.watchVM(id, rt)
	return a.applyEngine()
}

type gwStatus struct {
	Tunnels []struct {
		Name  string   `json:"name"`
		Addrs []string `json:"addrs"`
	} `json:"tunnels"`
	DefaultVia string   `json:"defaultVia"`
	DNS        []string `json:"dns"`
	Provision  string   `json:"provision"`
	Step       string   `json:"step"`  // the package being installed (agents of 0.3.1+)
	Error      string   `json:"error"` // why the setup failed, hyperv.SetupErr* (agents of 0.3.2+)
}

// setupErrorText says in words why the VM setup failed.
func setupErrorText(code string) string {
	switch code {
	case hyperv.SetupErrPackages:
		return i18n.T("app.vmSetupErrPackages")
	case hyperv.SetupErrGateway:
		return i18n.T("app.vmSetupErrGateway")
	case hyperv.SetupErrDesktop:
		return i18n.T("app.vmSetupErrDesktop")
	case hyperv.SetupErrAppPackages:
		return i18n.T("app.vmSetupErrAppPackages")
	case hyperv.SetupErrAppDownload:
		return i18n.T("app.vmSetupErrAppDownload")
	case hyperv.SetupErrAppInstall:
		return i18n.T("app.vmSetupErrAppInstall")
	}
	return code
}

// Files next to a VM: when it was created, and that its first setup ended.
const (
	vmCreatedFile = "created"
	vmSetUpFile   = "set-up"
)

// vmSetupStart is when the first setup of a VM began, or zero once it has
// ended. VMs made before 0.3.1 have no "created" file; their seed disk is
// written only when the VM is created.
func (a *App) vmSetupStart(id string) time.Time {
	dir := a.vmDir(id)
	if _, err := os.Stat(filepath.Join(dir, vmSetUpFile)); err == nil {
		return time.Time{}
	}
	if b, err := os.ReadFile(filepath.Join(dir, vmCreatedFile)); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64); err == nil {
			return time.Unix(n, 0)
		}
	}
	// The disk is created with the VM; its write time changes all along, and
	// so does the seed disk's (the VM mounts it), so the creation time counts.
	if t := fileCreated(filepath.Join(dir, "disk.vhdx")); !t.IsZero() && time.Since(t) < 6*time.Hour {
		return t
	}
	return time.Time{}
}

// setupDetail adds to a setup message how long the first setup has been
// running and which package it installs, and says when nothing seems to
// move, so it is clear the VM is still working.
func setupDetail(base string, start time.Time, now time.Time, step string, stuck bool) string {
	parts := []string{base}
	if !start.IsZero() {
		parts = append(parts, fmt.Sprintf(i18n.T("app.vmSetupFor"), max(1, int(now.Sub(start).Minutes()))))
	}
	if step != "" {
		parts = append(parts, fmt.Sprintf(i18n.T("app.vmSetupPackage"), step))
	}
	if stuck {
		parts = append(parts, i18n.T("app.vmSetupStuck"))
	}
	return strings.Join(parts, " · ")
}

// setupStuck: the same package for 15 minutes, or, with an agent that does
// not report packages, 40 minutes of setup in all.
func setupStuck(start, stepSince, now time.Time, step string) bool {
	if start.IsZero() {
		return false
	}
	if step != "" {
		return now.Sub(stepSince) > 15*time.Minute
	}
	return now.Sub(start) > 40*time.Minute
}

var gwClient = &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{Proxy: nil,
	DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}}

func (rt *vmRuntime) get(path string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, "http://"+rt.ip+":1081"+path, nil)
	req.SetBasicAuth(rt.user, rt.pass)
	resp, err := gwClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a *App) watchVM(id string, rt *vmRuntime) {
	t := time.NewTicker(4 * time.Second)
	defer t.Stop()
	started := time.Now()
	lastState := ""
	lastStep, stepSince := "", time.Now()
	for {
		var st gwStatus
		err := rt.get("/status", &st)
		state, detail, ip := "", "", ""
		var dns []string
		now := time.Now()
		if st.Step != lastStep {
			lastStep, stepSince = st.Step, now
		}
		setup := a.vmSetupStart(id)
		if err == nil && st.Provision == "done" && !setup.IsZero() {
			// the first setup has ended: no more "how long" from now on
			// (after an error it is retried, so it has not ended)
			os.WriteFile(filepath.Join(a.vmDir(id), vmSetUpFile), nil, 0o644)
			setup = time.Time{}
		}
		switch {
		case err != nil:
			state = "provisioning"
			detail = i18n.T("app.virtualMachineIsBooting")
			if time.Since(started) > 90*time.Second {
				detail = setupDetail(i18n.T("app.firstVmSetupUpTo"), setup, now, "", setupStuck(setup, stepSince, now, ""))
			}
		case len(st.Tunnels) == 0:
			state = "novpn"
			detail = i18n.T("app.openVmWindowAndConnect")
			if app := a.vmApp(id); app != "" {
				detail = i18n.T("app.vmAppConnecting")
			}
			if st.Provision == "running" {
				detail = i18n.T("app.vmIsStillBeingSet")
				if a.vmApp(id) != "" {
					detail = i18n.T("app.vmAppInstalling")
				}
				detail = setupDetail(detail, setup, now, st.Step, setupStuck(setup, stepSince, now, st.Step))
			}
			if st.Provision == "error" {
				if st.Error != "" {
					// agents of 0.3.2+: the reason, and the setup retries by itself
					detail = fmt.Sprintf(i18n.T("app.vmSetupFailedRetry"), setupErrorText(st.Error))
				} else if a.vmApp(id) != "" {
					detail = i18n.T("app.vmAppSetupFailed")
				}
			}
		default:
			state = "up"
			detail = fmt.Sprintf(i18n.T("app.tunnel"), st.Tunnels[0].Name)
			if len(st.Tunnels[0].Addrs) > 0 {
				ip = strings.Split(st.Tunnels[0].Addrs[0], "/")[0]
			}
			dns = st.DNS
		}
		if state != lastState {
			a.Log.Infof(id, "%s: %s", state, detail)
			lastState = state
		}
		if err == nil {
			a.deliverVMApp(id)
			a.pullVMAppLog(id, rt)
		}
		if state == "up" {
			a.vmDNS(id)
		}
		a.setConn(id, func(r *connRuntime) {
			if r.State != state {
				r.Since = time.Now().Unix()
			}
			r.State, r.Detail, r.IP, r.DNS = state, detail, ip, dns
		})
		select {
		case <-rt.stop:
			return
		case <-t.C:
		}
	}
}

func (a *App) vmStop(id string) {
	a.mu.Lock()
	rt := a.vms[id]
	delete(a.vms, id)
	delete(a.vmEndpoints, id)
	a.mu.Unlock()
	if rt == nil {
		return
	}
	close(rt.stop)
	// Save rather than shut down: the VPN app session survives and resumes fast.
	if err := hyperv.Save(rt.name); err != nil {
		a.Log.Warnf(id, i18n.T("app.pausingVm"), err)
	}
}

func (a *App) vmName(id string) (string, bool) {
	c := a.Config().Conn(id)
	if c == nil {
		return "", false
	}
	p, err := providers.Get(c.Type)
	if err != nil {
		return "", false
	}
	vp, ok := p.(providers.VMProvider)
	if !ok {
		return "", false
	}
	spec, err := vp.VM(c)
	if err != nil {
		return "", false
	}
	return spec.VMName, true
}

// OpenConsole shows the VM window (starting the VM if needed).
func (a *App) OpenConsole(id string) error {
	name, ok := a.vmName(id)
	if !ok {
		return errors.New(i18n.T("app.thisConnectionIsNotVirtual"))
	}
	if !hyperv.Exists(name) {
		return errors.New(i18n.T("app.virtualMachineIsNotCreated"))
	}
	return hyperv.OpenConsole(name)
}

// removeVM deletes the VM and its disks (when the connection is deleted).
func (a *App) removeVM(id string) {
	name, ok := a.vmName(id)
	if !ok {
		return
	}
	if err := hyperv.Remove(name, a.vmDir(id)); err != nil {
		a.Log.Warnf(id, i18n.T("app.deletingVm"), err)
	} else {
		a.Log.Infof(id, i18n.T("app.virtualMachineDeleted"), name)
	}
}

// Files in the VM's folder on the host: the app VPNer set up in it, and the
// hash of the subscription link last handed to that app.
const (
	vmAppFile = "app"
	vmSubSent = "subscription.sent"
)

// vmHostname is the computer name of a new VM: the device name the user
// chose, or VPNer's own.
func vmHostname(id string, spec *providers.VMSpec) string {
	if spec.Hostname != "" {
		return spec.Hostname
	}
	return "vpner-" + id
}

// vmApp returns the program VPNer set up in the VM of a connection.
func (a *App) vmApp(id string) string {
	b, err := os.ReadFile(filepath.Join(a.vmDir(id), vmAppFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

var vmDeliverTry sync.Map // connection id -> time of the last attempt

// deliverVMApp hands the app in the VM the subscription link the user
// entered, once per link: the app adds a subscription every time it gets
// one. The link travels over the gateway's channel into the shared folder,
// where a script of the VM passes it to the app and deletes it; it is never
// written to the VM's setup disk.
func (a *App) deliverVMApp(id string) {
	if a.vmApp(id) != hyperv.AppIncy {
		return
	}
	c := a.Config().Conn(id)
	if c == nil {
		return
	}
	link := NormalizeSubscription(c.S("subscription"))
	if link == "" {
		return
	}
	sum := sha256.Sum256([]byte(link))
	mark := filepath.Join(a.vmDir(id), vmSubSent)
	if b, _ := os.ReadFile(mark); strings.TrimSpace(string(b)) == hex.EncodeToString(sum[:]) {
		return
	}
	// The status is checked every few seconds; a failed attempt is retried
	// at most every half minute.
	if t, ok := vmDeliverTry.Load(id); ok && time.Since(t.(time.Time)) < 30*time.Second {
		return
	}
	vmDeliverTry.Store(id, time.Now())
	if err := a.VMUpload(id, hyperv.IncySubscriptionFile, strings.NewReader(link+"\n")); err != nil {
		a.Log.Warnf(id, i18n.T("app.vmAppSubscriptionNotSent"), err)
		return
	}
	if err := os.WriteFile(mark, []byte(hex.EncodeToString(sum[:])), 0o644); err != nil {
		a.Log.Warnf(id, "%v", err)
	}
	a.Log.Infof(id, "%s", i18n.T("app.vmAppSubscriptionSent"))
}

// vmDNSFile marks that VPNer has set up the VM's DNS server (vm_dns.go): it
// is done once, so a server the user deleted or a default the user changed
// afterwards stays as the user left it.
const vmDNSFile = "dns.added"

var vmDNSTry sync.Map // connection id -> time of the last attempt

// vmDNS adds the DNS server of a VM with a VPN program VPNer set up, once
// that VPN passes traffic: the server must answer through it first.
func (a *App) vmDNS(id string) {
	if a.vmApp(id) == "" {
		return
	}
	mark := filepath.Join(a.vmDir(id), vmDNSFile)
	if _, err := os.Stat(mark); err == nil {
		return
	}
	if t, ok := vmDNSTry.Load(id); ok && time.Since(t.(time.Time)) < time.Minute {
		return
	}
	vmDNSTry.Store(id, time.Now())
	a.mu.Lock()
	port, running := a.testPorts[id], a.running
	a.mu.Unlock()
	if !running || port == 0 {
		return
	}
	go func() {
		if err := dohWorks(fmt.Sprintf("http://127.0.0.1:%d", port)); err != nil {
			return // the VPN passes nothing yet: tried again in a minute
		}
		a.ops.Lock()
		cfg := a.Config()
		c := cfg.Conn(id)
		if c == nil {
			a.ops.Unlock()
			return
		}
		changed, def := withVMDNS(&cfg.DNS, id, c.Name)
		var err error
		if changed {
			err = a.commit(cfg)
		}
		a.ops.Unlock()
		if err != nil {
			a.Log.Warnf(id, "%v", err)
			return
		}
		os.WriteFile(mark, nil, 0o644)
		name := fmt.Sprintf(i18n.T("app.cloudflareViaConn"), c.Name)
		switch {
		case def:
			a.Log.Infof(id, i18n.T("app.vmDnsAddedDefault"), name)
		case changed:
			a.Log.Infof(id, i18n.T("app.vmDnsAdded"), name)
		}
	}()
}

// vmLogMark keeps how far VPNer has read the log of the VM's VPN program,
// so that a restart of VPNer does not show it again.
const vmLogMark = "applog.offset"

// pullVMAppLog copies the new lines of the VM's VPN program log (INCY) into
// VPNer's log, under the VM connection: everything in one place. Agents
// older than 0.3.4 have no log to give; nothing is shown for them.
func (a *App) pullVMAppLog(id string, rt *vmRuntime) {
	app := a.vmApp(id)
	if app == "" {
		return
	}
	mark := filepath.Join(a.vmDir(id), vmLogMark)
	var off int64 = -1 // never read: only the end of the log is shown
	if b, err := os.ReadFile(mark); err == nil {
		off, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	}
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s:1081/applog?name=incy.log&offset=%d", rt.ip, max(off, 0)), nil)
	req.SetBasicAuth(rt.user, rt.pass)
	resp, err := gwClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	from, _ := strconv.ParseInt(resp.Header.Get("X-Log-Offset"), 10, 64)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}
	// Whole lines only; a line still being written comes next time.
	n := bytes.LastIndexByte(body, '\n') + 1
	lines := strings.Split(strings.TrimRight(string(body[:n]), "\r\n"), "\n")
	if off < 0 && len(lines) > 30 {
		lines = lines[len(lines)-30:]
	}
	name := appTitle(app)
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if l := strings.ToLower(line); strings.Contains(l, "[warning]") || strings.Contains(l, "[error") || strings.Contains(l, "/error]") {
			a.Log.Warnf(id, "%s: %s", name, line)
		} else {
			a.Log.Infof(id, "%s: %s", name, line)
		}
	}
	if next := from + int64(n); next != off {
		os.WriteFile(mark, []byte(strconv.FormatInt(next, 10)), 0o644)
	}
}

// appTitle names a VM's VPN program in VPNer's log.
func appTitle(app string) string {
	if app == hyperv.AppIncy {
		return "INCY"
	}
	return app
}

// VMUpload sends a file into the VM's shared folder.
func (a *App) VMUpload(id, name string, body io.Reader) error {
	a.mu.Lock()
	rt := a.vms[id]
	a.mu.Unlock()
	if rt == nil {
		return errors.New(i18n.T("app.connectVirtualMachineFirst"))
	}
	req, _ := http.NewRequest(http.MethodPost, "http://"+rt.ip+":1081/upload?name="+url.QueryEscape(filepath.Base(name)), body)
	req.SetBasicAuth(rt.user, rt.pass)
	resp, err := (&http.Client{Timeout: 30 * time.Minute, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return fmt.Errorf(i18n.T("app.vmGatewayIsUnreachable"), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf(i18n.T("app.vmRejectedFile"), strings.TrimSpace(string(b)))
	}
	a.Log.Infof(id, i18n.T("app.fileSentToVmFiles"), filepath.Base(name))
	return nil
}

// HyperVStatus for the settings page.
func HyperVStatus() string {
	if err := hyperv.Available(); err != nil {
		return err.Error()
	}
	return ""
}

func EnableHyperV() (string, error) { return hyperv.Enable() }
