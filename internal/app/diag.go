package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"vpner/internal/config"
	"vpner/internal/providers"
)

// ---- leak test ----

type ExitInfo struct {
	Target    string   `json:"target"`
	Name      string   `json:"name"`
	IP        string   `json:"ip,omitempty"`
	Country   string   `json:"country,omitempty"`
	Colo      string   `json:"colo,omitempty"`
	IPv6      string   `json:"ipv6,omitempty"`
	LatencyMS int64    `json:"latencyMs,omitempty"`
	DNS       []string `json:"dns,omitempty"`
	Error     string   `json:"error,omitempty"`
	Verdict   string   `json:"verdict"` // ok|leak|error|direct|info
	Note      string   `json:"note,omitempty"`
}

type LeakReport struct {
	Time   int64      `json:"time"`
	Direct ExitInfo   `json:"direct"`
	Exits  []ExitInfo `json:"exits"`
}

func trace(client *http.Client, u string) (map[string]string, time.Duration, error) {
	t := time.Now()
	resp, err := client.Get(u)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, 0, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			out[k] = v
		}
	}
	if out["ip"] == "" {
		return nil, 0, fmt.Errorf("неожиданный ответ")
	}
	return out, time.Since(t), nil
}

func clientVia(proxy string) *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	if proxy != "" {
		u, _ := url.Parse(proxy)
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

const (
	traceV4 = "https://1.1.1.1/cdn-cgi/trace"
	traceV6 = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
)

// LeakTest reports the exit IP of the real connection and of every active
// VPN, and flags any VPN whose exit IP equals the real one.
func (a *App) LeakTest(ctx context.Context) (*LeakReport, error) {
	if !a.Running() {
		return nil, fmt.Errorf("маршрутизация выключена")
	}
	rep := &LeakReport{Time: time.Now().Unix()}
	probe := func(proxy string, info *ExitInfo) {
		c := clientVia(proxy)
		m, d, err := trace(c, traceV4)
		if err != nil {
			info.Error = err.Error()
			info.Verdict = "error"
			return
		}
		info.IP, info.Country, info.Colo, info.LatencyMS = m["ip"], m["loc"], m["colo"], d.Milliseconds()
		if m6, _, err := trace(c, traceV6); err == nil {
			info.IPv6 = m6["ip"]
		}
	}
	rep.Direct = ExitInfo{Target: config.TargetDirect, Name: "Без VPN (ваш реальный адрес)", Verdict: "direct"}
	probe("", &rep.Direct)

	snap := a.Snapshot()
	cfg := a.Config()
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, cv := range snap.Connections {
		if !cv.Enabled || cv.LocalProxy == 0 {
			continue
		}
		cv := cv
		wg.Add(1)
		go func() {
			defer wg.Done()
			info := ExitInfo{Target: cv.ID, Name: cv.Name, DNS: cv.DNS, Verdict: "ok"}
			if cv.Runtime != string(providers.RuntimeNative) && cv.State != "up" {
				info.Verdict = "info"
				info.Note = "не подключено — трафик по правилам для него блокируется"
			} else {
				probe(fmt.Sprintf("http://127.0.0.1:%d", cv.LocalProxy), &info)
			}
			c := cfg.Conn(cv.ID)
			if info.Verdict == "ok" && info.IP != "" {
				if c != nil && c.Type == "interface" {
					info.Verdict = "info"
					info.Note = "выход через сетевой интерфейс, а не VPN"
				} else if info.IP == rep.Direct.IP {
					info.Verdict = "leak"
					info.Note = "выходной адрес совпадает с реальным — этот «VPN» трафик не прячет"
				} else if info.IPv6 != "" && info.IPv6 == rep.Direct.IPv6 {
					info.Verdict = "leak"
					info.Note = "IPv6 совпадает с реальным"
				}
			}
			mu.Lock()
			rep.Exits = append(rep.Exits, info)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(rep.Exits, func(i, j int) bool { return rep.Exits[i].Name < rep.Exits[j].Name })
	return rep, nil
}

// ---- route check: where would this go? ----

type RouteCheck struct {
	Target     string `json:"target"`
	TargetName string `json:"targetName"`
	Rule       string `json:"rule"`
	Note       string `json:"note,omitempty"`
}

// CheckRoute evaluates VPNer rules for a domain/IP and optional process name
// the same way the engine orders them.
func (a *App) CheckRoute(host, process string) RouteCheck {
	cfg := a.Config()
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	process = strings.ToLower(strings.TrimSpace(process))
	ip := net.ParseIP(host)
	var notes []string
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		for _, raw := range r.Values {
			v := strings.ToLower(strings.TrimSpace(raw))
			if v == "" {
				continue
			}
			hit := false
			switch r.Kind {
			case config.RuleProcess:
				if process != "" {
					hit = globMatch(v, process)
				}
			case config.RuleProcessPath:
				if process != "" && strings.Contains(v, `\`) {
					hit = globMatch(v, process) || strings.HasSuffix(v, `\`+process)
				}
			case config.RuleDomain:
				d := strings.TrimPrefix(v, "*.")
				hit = ip == nil && (host == d || (strings.HasPrefix(v, "*.") && strings.HasSuffix(host, "."+d)))
			case config.RuleDomainSuffix:
				d := strings.TrimPrefix(strings.TrimPrefix(v, "*."), ".")
				hit = ip == nil && (host == d || strings.HasSuffix(host, "."+d))
			case config.RuleDomainKeyword:
				hit = ip == nil && strings.Contains(host, v)
			case config.RuleDomainRegex:
				if re, err := regexp.Compile(raw); err == nil {
					hit = ip == nil && re.MatchString(host)
				}
			case config.RuleIPCIDR:
				if ip != nil {
					c := v
					if !strings.Contains(c, "/") {
						c += "/32"
					}
					if _, n, err := net.ParseCIDR(c); err == nil {
						hit = n.Contains(ip)
					}
				}
			case config.RuleGeoSite, config.RuleGeoIP:
				notes = append(notes, fmt.Sprintf("правило %s:%s проверяется только движком", r.Kind, v))
			}
			if hit {
				return RouteCheck{Target: r.Target, TargetName: a.ConnName(r.Target), Rule: fmt.Sprintf("%s: %s", kindTitle(r.Kind), raw), Note: strings.Join(notes, "; ")}
			}
		}
	}
	if cfg.Settings.AllowLAN && ip != nil && (ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()) {
		return RouteCheck{Target: config.TargetDirect, TargetName: a.ConnName(config.TargetDirect), Rule: "локальная сеть"}
	}
	return RouteCheck{Target: cfg.Settings.FinalTarget, TargetName: a.ConnName(cfg.Settings.FinalTarget), Rule: "правило по умолчанию", Note: strings.Join(notes, "; ")}
}

func globMatch(pattern, s string) bool {
	re := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"), `\?`, ".") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}

func kindTitle(k string) string {
	switch k {
	case config.RuleProcess:
		return "программа"
	case config.RuleProcessPath:
		return "путь программы"
	case config.RuleDomain:
		return "домен"
	case config.RuleDomainSuffix:
		return "домен с поддоменами"
	case config.RuleDomainKeyword:
		return "домен содержит"
	case config.RuleDomainRegex:
		return "домен (regex)"
	case config.RuleIPCIDR:
		return "IP/подсеть"
	case config.RuleGeoSite:
		return "категория сайтов"
	case config.RuleGeoIP:
		return "страна IP"
	case config.RuleDstPort:
		return "порт"
	case config.RuleNetwork:
		return "протокол"
	}
	return k
}

// ---- live connections ----

type LiveConn struct {
	ID       string `json:"id"`
	Process  string `json:"process"`
	Host     string `json:"host"`
	Dest     string `json:"dest"`
	Network  string `json:"network"`
	Via      string `json:"via"`
	ViaName  string `json:"viaName"`
	Rule     string `json:"rule"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Start    string `json:"start"`
}

type LiveView struct {
	Up    int64      `json:"uploadTotal"`
	Down  int64      `json:"downloadTotal"`
	Conns []LiveConn `json:"connections"`
}

func (a *App) Live() (*LiveView, error) {
	m := a.Engine()
	if m == nil {
		return &LiveView{Conns: []LiveConn{}}, nil
	}
	c, err := m.Connections()
	if err != nil {
		return nil, err
	}
	v := &LiveView{Up: c.UploadTotal, Down: c.DownloadTotal, Conns: []LiveConn{}}
	for _, x := range c.Connections {
		via := ""
		if len(x.Chains) > 0 {
			via = x.Chains[0]
		}
		host := x.Metadata.Host
		if host == "" {
			host = x.Metadata.SniffHost
		}
		rule := x.Rule
		if x.Payload != "" {
			rule += " " + x.Payload
		}
		v.Conns = append(v.Conns, LiveConn{
			ID: x.ID, Process: x.Metadata.Process, Host: host,
			Dest:    net.JoinHostPort(x.Metadata.DestIP, x.Metadata.DestPort),
			Network: x.Metadata.Network, Via: via, ViaName: a.ConnName(via), Rule: rule,
			Upload: x.Upload, Download: x.Download, Start: x.Start,
		})
	}
	sort.Slice(v.Conns, func(i, j int) bool { return v.Conns[i].Start > v.Conns[j].Start })
	return v, nil
}
