//go:build linux

package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"vpner/internal/bridge"
)

const hookSock = runRoot + "/agent.sock"

// hookMsg is sent by hook scripts (running inside a namespace as children of
// a VPN daemon) to the agent.
type hookMsg struct {
	ID    string   `json:"id"`
	Event string   `json:"event"` // up|down|reconnecting|openurl|log
	Tun   string   `json:"tun,omitempty"`
	IP    string   `json:"ip,omitempty"`
	DNS   []string `json:"dns,omitempty"`
	URL   string   `json:"url,omitempty"`
	Line  string   `json:"line,omitempty"`
}

func (a *Agent) serveHooks() {
	os.Remove(hookSock)
	l, err := net.Listen("unix", hookSock)
	if err != nil {
		log.Printf("hook socket: %v", err)
		return
	}
	os.Chmod(hookSock, 0o600)
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			var m hookMsg
			if err := bridge.ReadJSONLine(bufio.NewReader(c), &m); err != nil {
				return
			}
			err := a.onHook(m)
			resp := "ok\n"
			if err != nil {
				resp = "error: " + err.Error() + "\n"
			}
			c.Write([]byte(resp))
		}(c)
	}
}

func (a *Agent) onHook(m hookMsg) error {
	c, err := a.get(m.ID)
	if err != nil {
		return err
	}
	switch m.Event {
	case "up":
		c.reportUp(m.Tun, m.IP, m.DNS)
	case "down":
		c.mu.Lock()
		c.sawUp, c.pending = false, nil
		c.mu.Unlock()
		c.setState("down", "туннель закрыт")
	case "reconnecting":
		c.setState("starting", "переподключение")
	case "log":
		c.log(m.Line)
	case "openurl":
		c.log("открываю страницу входа в браузере: " + m.URL)
		bc, _, err := bridge.Open(a.sess, bridge.Header{Op: bridge.OpOpenURL, Conn: m.ID, URL: m.URL})
		if err != nil {
			return err
		}
		bc.Close()
	default:
		return fmt.Errorf("unknown hook event %q", m.Event)
	}
	return nil
}

func sendHook(m hookMsg) error {
	c, err := net.DialTimeout("unix", hookSock, 5*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := bridge.WriteJSONLine(c, m); err != nil {
		return err
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if strings.HasPrefix(line, "error: ") {
		return errors.New(strings.TrimSpace(strings.TrimPrefix(line, "error: ")))
	}
	return nil
}

func loadHookState(id string) hookState {
	var hs hookState
	dir := os.Getenv("VPNER_DIR")
	if dir == "" {
		dir = filepath.Join(runRoot, id) // daemons may strip the environment
	}
	if b, err := os.ReadFile(filepath.Join(dir, "hook.json")); err == nil {
		json.Unmarshal(b, &hs)
	}
	return hs
}

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func hookLog(id, line string) {
	fmt.Fprintln(os.Stderr, "vpner-hook:", line)
	sendHook(hookMsg{ID: id, Event: "log", Line: "hook: " + line})
}

// Hook is the entry point for "vpner-agent hook <kind> <id> [args...]".
func Hook(kind, id string, args []string) error {
	// OpenVPN runs scripts with a minimal environment that has no PATH, so
	// commands like "ip" would not be found and routes would silently be
	// missing. Always provide the standard system path.
	if !strings.Contains(os.Getenv("PATH"), "/sbin") {
		os.Setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	}
	switch kind {
	case "vpnc":
		return hookVPNC(id)
	case "ovpn-up":
		return hookOVPNUp(id)
	case "ovpn-down":
		return sendHook(hookMsg{ID: id, Event: "down"})
	case "openurl":
		if len(args) < 1 {
			return errors.New("openurl: missing url")
		}
		return sendHook(hookMsg{ID: id, Event: "openurl", URL: args[0]})
	}
	return fmt.Errorf("unknown hook %q", kind)
}

// hookVPNC replaces vpnc-script for openconnect. It runs inside the
// connection's namespace, so it only ever touches that namespace's routes.
func hookVPNC(id string) error {
	reason := os.Getenv("reason")
	switch reason {
	case "pre-init":
		return nil
	case "attempt-reconnect":
		return sendHook(hookMsg{ID: id, Event: "reconnecting"})
	case "disconnect":
		return sendHook(hookMsg{ID: id, Event: "down"})
	case "connect", "reconnect":
	default:
		return nil
	}
	hs := loadHookState(id)
	tun := os.Getenv("TUNDEV")
	addr := os.Getenv("INTERNAL_IP4_ADDRESS")
	if tun == "" || addr == "" {
		return errors.New("vpnc: TUNDEV/INTERNAL_IP4_ADDRESS not set (IPv6-only tunnels are not supported)")
	}
	mtu := os.Getenv("INTERNAL_IP4_MTU")
	if mtu == "" {
		mtu = "1300"
	}
	if err := ip("link", "set", "dev", tun, "up", "mtu", mtu); err != nil {
		return err
	}
	if reason == "connect" {
		ip("addr", "replace", addr+"/32", "peer", addr, "dev", tun)
	}
	dns := strings.Fields(os.Getenv("INTERNAL_IP4_DNS"))
	n, _ := strconv.Atoi(os.Getenv("CISCO_SPLIT_INC"))
	var routes []string
	if n > 0 && !hs.RouteAll {
		for i := 0; i < n; i++ {
			a := os.Getenv(fmt.Sprintf("CISCO_SPLIT_INC_%d_ADDR", i))
			ml := os.Getenv(fmt.Sprintf("CISCO_SPLIT_INC_%d_MASKLEN", i))
			if a == "" || ml == "" {
				continue
			}
			if a == "0.0.0.0" && ml == "0" {
				routes = append(routes, "0.0.0.0/1", "128.0.0.0/1")
				continue
			}
			routes = append(routes, a+"/"+ml)
		}
		for _, d := range dns {
			routes = append(routes, d+"/32")
		}
	} else {
		routes = []string{"0.0.0.0/1", "128.0.0.0/1"}
	}
	for _, r := range routes {
		if err := ip("route", "replace", r, "dev", tun); err != nil {
			hookLog(id, err.Error())
		}
	}
	hookLog(id, fmt.Sprintf("tun %s addr %s mtu %s routes %v dns %v", tun, addr, mtu, routes, dns))
	return sendHook(hookMsg{ID: id, Event: "up", Tun: tun, IP: addr, DNS: dns})
}

var dhcpDNSRe = regexp.MustCompile(`(?i)^dhcp-option\s+DNS\s+(\S+)`)

// hookOVPNUp runs as OpenVPN's --route-up script inside the namespace.
func hookOVPNUp(id string) error {
	hs := loadHookState(id)
	tun := os.Getenv("dev")
	addr := os.Getenv("ifconfig_local")
	var dns []string
	var keys []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "foreign_option_") || strings.HasPrefix(k, "dns_server_") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := os.Getenv(k)
		if strings.HasPrefix(k, "foreign_option_") {
			if m := dhcpDNSRe.FindStringSubmatch(v); m != nil {
				dns = append(dns, m[1])
			}
		} else if strings.Contains(k, "_address_") && net.ParseIP(v).To4() != nil {
			dns = append(dns, v)
		}
	}
	dns = uniq(dns)
	if hs.RouteAll && tun != "" {
		for _, r := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			if err := ip("route", "replace", r, "dev", tun); err != nil {
				hookLog(id, err.Error())
			}
		}
	}
	if tun != "" {
		for _, d := range dns {
			ip("route", "replace", d+"/32", "dev", tun)
		}
	}
	hookLog(id, fmt.Sprintf("tun %s addr %s dns %v", tun, addr, dns))
	return sendHook(hookMsg{ID: id, Event: "up", Tun: tun, IP: addr, DNS: dns})
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
