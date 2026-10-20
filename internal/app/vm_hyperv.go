package app

import (
	"vpner/internal/i18n"

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
			ID: id + "-" + randHex(3), Hostname: "vpner-" + id, LANIP: c.P("lanIp"),
			WANMac: hyperv.MACColon(c.P("wanMac")), LANMac: hyperv.MACColon(c.P("lanMac")),
			GatewayUser: "vpner", GatewayPass: c.S("gwPass"), ConsolePass: c.P("consolePassword"),
			Desktop: spec.Desktop, FallbackDNS: spec.DNS, Agent: agent,
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
	for {
		var st gwStatus
		err := rt.get("/status", &st)
		state, detail, ip := "", "", ""
		var dns []string
		switch {
		case err != nil:
			state = "provisioning"
			detail = i18n.T("app.virtualMachineIsBooting")
			if time.Since(started) > 90*time.Second {
				detail = i18n.T("app.firstVmSetupUpTo")
			}
		case len(st.Tunnels) == 0:
			state = "novpn"
			detail = i18n.T("app.openVmWindowAndConnect")
			if st.Provision == "running" {
				detail = i18n.T("app.vmIsStillBeingSet")
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
