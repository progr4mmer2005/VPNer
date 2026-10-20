//go:build linux

package agent

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"vpner/internal/socks5"
)

// GatewayConfig is written by cloud-init into a VPN virtual machine.
type GatewayConfig struct {
	Listen      string   `json:"listen"` // lan IP of the VM
	HostIP      string   `json:"hostIp"` // the only peer allowed
	User        string   `json:"user"`   // SOCKS5 / status credentials
	Pass        string   `json:"pass"`
	FallbackDNS []string `json:"fallbackDns"` // used when the VPN app sets no DNS
	ShareDir    string   `json:"shareDir"`
	WANIface    string   `json:"wanIface"`
	LANIface    string   `json:"lanIface"`
}

// GatewayStatus is served to the host.
type GatewayStatus struct {
	Version    string   `json:"version"`
	Tunnels    []Tunnel `json:"tunnels"`
	DefaultVia string   `json:"defaultVia"`
	DNS        []string `json:"dns"`
	Provision  string   `json:"provision"` // running|done|error
	Uptime     int64    `json:"uptime"`
}

type Tunnel struct {
	Name  string   `json:"name"`
	Addrs []string `json:"addrs"`
}

// Gateway runs the SOCKS5 gateway inside a VPN virtual machine. The process
// runs as a dedicated user; nftables (loaded by systemd before start) only
// lets that user send packets through tunnel interfaces, never through the
// VM's own uplink, so nothing can bypass the VPN application.
func Gateway(cfgPath string) error {
	log.SetFlags(log.LstdFlags)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	var cfg GatewayConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return err
	}
	if cfg.WANIface == "" {
		cfg.WANIface = "wan0"
	}
	if cfg.LANIface == "" {
		cfg.LANIface = "lan0"
	}
	g := &gateway{cfg: cfg, start: time.Now(), cache: map[string]cacheEntry{}}
	l, err := listenRetry("tcp4", net.JoinHostPort(cfg.Listen, "1080"))
	if err != nil {
		return err
	}
	srv := &socks5.Server{Backend: g, User: cfg.User, Pass: cfg.Pass, Logf: log.Printf}
	go srv.Serve(l)

	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(g.status())
	})
	mux.HandleFunc("/upload", g.upload)
	hl, err := listenRetry("tcp4", net.JoinHostPort(cfg.Listen, "1081"))
	if err != nil {
		return err
	}
	log.Printf("vpner gateway %s on %s", Version, cfg.Listen)
	return (&http.Server{Handler: g.auth(mux), ReadHeaderTimeout: 10 * time.Second}).Serve(hl)
}

// The LAN address may appear a little after the service starts.
func listenRetry(network, addr string) (net.Listener, error) {
	var err error
	for i := 0; i < 60; i++ {
		var l net.Listener
		if l, err = net.Listen(network, addr); err == nil {
			return l, nil
		}
		time.Sleep(2 * time.Second)
	}
	return nil, err
}

type gateway struct {
	cfg   GatewayConfig
	start time.Time
	mu    sync.Mutex
	cache map[string]cacheEntry
}

func (g *gateway) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(u), []byte(g.cfg.User)) != 1 || subtle.ConstantTimeCompare([]byte(p), []byte(g.cfg.Pass)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var skipIfaceRe = regexp.MustCompile(`^(lo|docker\d*|br-.*|veth.*|virbr.*|vnet.*)$`)

func (g *gateway) tunnels() []Tunnel {
	ifs, _ := net.Interfaces()
	var out []Tunnel
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Name == g.cfg.WANIface || i.Name == g.cfg.LANIface || skipIfaceRe.MatchString(i.Name) {
			continue
		}
		addrs, _ := i.Addrs()
		var v4 []string
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
				v4 = append(v4, ipn.String())
			}
		}
		if len(v4) > 0 {
			out = append(out, Tunnel{Name: i.Name, Addrs: v4})
		}
	}
	return out
}

func defaultRouteIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	best, bestMask := "", -1
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) < 8 || fl[0] == "Iface" {
			continue
		}
		// 0.0.0.0/0 or the 0/1 + 128/1 pair used by most VPN clients
		if fl[1] == "00000000" && fl[7] == "00000000" && bestMask < 0 {
			best, bestMask = fl[0], 0
		}
		if (fl[1] == "00000000" || fl[1] == "00000080") && fl[7] == "00000080" {
			best, bestMask = fl[0], 1
		}
	}
	return best
}

func provisionState() string {
	if _, err := os.Stat("/var/lib/cloud/instance/boot-finished"); err == nil {
		b, _ := os.ReadFile("/run/cloud-init/result.json")
		if strings.Contains(string(b), `"errors": [`) && !strings.Contains(string(b), `"errors": []`) {
			return "error"
		}
		return "done"
	}
	return "running"
}

func (g *gateway) status() GatewayStatus {
	return GatewayStatus{Version: Version, Tunnels: g.tunnels(), DefaultVia: defaultRouteIface(), DNS: g.dnsServers(),
		Provision: provisionState(), Uptime: int64(time.Since(g.start).Seconds())}
}

var resolvectlLinkRe = regexp.MustCompile(`^Link \d+ \(([^)]+)\):\s*(.*)$`)

// dnsServers picks DNS servers that are reachable only through the tunnel:
// those the VPN app configured on its tunnel links, then non-loopback
// servers from resolv.conf, then the configured fallback. The local stub
// (127.0.0.53) is never used: it could send the query out of the uplink.
func (g *gateway) dnsServers() []string {
	tun := map[string]bool{}
	for _, t := range g.tunnels() {
		tun[t.Name] = true
	}
	var out []string
	if b, err := exec.Command("resolvectl", "dns").Output(); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if m := resolvectlLinkRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && tun[m[1]] {
				for _, s := range strings.Fields(m[2]) {
					if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
						out = append(out, s)
					}
				}
			}
		}
	}
	// Servers on the VM's own uplink subnet (the home router) are reachable
	// only outside the tunnel; the kill switch would drop them anyway.
	var wanNets []*net.IPNet
	if wi, err := net.InterfaceByName(g.cfg.WANIface); err == nil {
		addrs, _ := wi.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				wanNets = append(wanNets, n)
			}
		}
	}
	onWAN := func(ip net.IP) bool {
		for _, n := range wanNets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "nameserver" {
				if ip := net.ParseIP(f[1]); ip != nil && ip.To4() != nil && !ip.IsLoopback() && !onWAN(ip) {
					out = append(out, f[1])
				}
			}
		}
	}
	out = append(out, g.cfg.FallbackDNS...)
	return uniq(out)
}

func (g *gateway) resolve(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", errors.New("ipv6 is not supported by the gateway")
		}
		return addr, nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	g.mu.Lock()
	if e, ok := g.cache[host]; ok && time.Now().Before(e.expires) {
		g.mu.Unlock()
		return net.JoinHostPort(e.ips[0].String(), port), nil
	}
	g.mu.Unlock()
	var lastErr error
	for _, s := range g.dnsServers() {
		ips, ttl, err := queryDirect(s, host)
		if err != nil {
			lastErr = err
			continue
		}
		if len(ips) == 0 {
			return "", fmt.Errorf("resolve %s: no such host", host)
		}
		if ttl < 30 {
			ttl = 30
		}
		g.mu.Lock()
		g.cache[host] = cacheEntry{ips: ips, expires: time.Now().Add(time.Duration(min(ttl, 3600)) * time.Second)}
		g.mu.Unlock()
		return net.JoinHostPort(ips[0].String(), port), nil
	}
	return "", fmt.Errorf("resolve %s: %v", host, lastErr)
}

// queryDirect sends a DNS query from this process (and thus through the
// tunnel only, enforced by nftables).
func queryDirect(server, name string) ([]net.IP, uint32, error) {
	r := &tunnelResolver{}
	return r.queryWith(server, name, func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, 4*time.Second)
	})
}

func (g *gateway) DialTCP(addr string) (net.Conn, error) {
	if len(g.tunnels()) == 0 {
		return nil, errors.New("VPN in the VM is not connected")
	}
	ra, err := g.resolve(addr)
	if err != nil {
		return nil, err
	}
	if ip := net.ParseIP(strings.Split(ra, ":")[0]); ip == nil || ip.IsLoopback() {
		return nil, errors.New("loopback destinations are not allowed")
	}
	return net.DialTimeout("tcp4", ra, 15*time.Second)
}

func (g *gateway) OpenUDP() (socks5.UDPSession, error) {
	if len(g.tunnels()) == 0 {
		return nil, errors.New("VPN in the VM is not connected")
	}
	pc, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	return &gwUDP{g: g, pc: pc}, nil
}

type gwUDP struct {
	g  *gateway
	pc *net.UDPConn
}

func (u *gwUDP) Send(addr string, p []byte) error {
	ra, err := u.g.resolve(addr)
	if err != nil {
		return err
	}
	ua, err := net.ResolveUDPAddr("udp4", ra)
	if err != nil || ua.IP.IsLoopback() {
		return errors.New("bad destination")
	}
	_, err = u.pc.WriteToUDP(p, ua)
	return err
}

func (u *gwUDP) Recv(buf []byte) (string, []byte, error) {
	n, from, err := u.pc.ReadFromUDP(buf)
	if err != nil {
		return "", nil, err
	}
	return from.String(), buf[:n], nil
}

func (u *gwUDP) Close() error { return u.pc.Close() }

// upload stores a file from the host into the shared folder of the VM (for
// VPN client installers, configs, certificates).
func (g *gateway) upload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	name := filepath.Base(r.URL.Query().Get("name"))
	if name == "" || name == "." || name == "/" || strings.HasPrefix(name, ".") {
		http.Error(w, "bad name", http.StatusBadRequest)
		return
	}
	dir := g.cfg.ShareDir
	if dir == "" {
		dir = "/srv/vpner-share"
	}
	dst := filepath.Join(dir, name)
	f, err := os.OpenFile(dst+".part", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o664)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = io.Copy(f, io.LimitReader(r.Body, 4<<30))
	f.Close()
	if err == nil {
		err = os.Rename(dst+".part", dst)
	}
	if err != nil {
		os.Remove(dst + ".part")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(name, ".run") || strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".AppImage") {
		os.Chmod(dst, 0o775)
	}
	json.NewEncoder(w).Encode(map[string]string{"path": dst})
}

var _ = context.Background
