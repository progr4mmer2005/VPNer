package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Mihomo supervises the mihomo process.
type Mihomo struct {
	Bin     string // path to mihomo.exe
	WorkDir string // config/data directory
	Logf    func(level, line string)

	Port   int
	Secret string

	mu      sync.Mutex
	cmd     *exec.Cmd
	exited  chan struct{}
	lastErr string
}

func (m *Mihomo) configPath() string { return filepath.Join(m.WorkDir, "config.yaml") }

func (m *Mihomo) writeConfig(conf map[string]any) error {
	b, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.WorkDir, 0o700); err != nil {
		return err
	}
	tmp := m.configPath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.configPath())
}

// Test validates a config with "mihomo -t" without applying it.
func (m *Mihomo) Test(conf map[string]any) error {
	b, err := yaml.Marshal(conf)
	if err != nil {
		return err
	}
	os.MkdirAll(m.WorkDir, 0o700)
	p := filepath.Join(m.WorkDir, "config.test.yaml")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(p)
	cmd := exec.Command(m.Bin, "-t", "-d", m.WorkDir, "-f", p)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("конфигурация движка отклонена: %s", lastLines(string(out), 6))
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (m *Mihomo) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil
}

// Start writes the config and launches mihomo, waiting until its API answers.
func (m *Mihomo) Start(conf map[string]any) error {
	if err := m.writeConfig(conf); err != nil {
		return err
	}
	m.mu.Lock()
	if m.cmd != nil {
		m.mu.Unlock()
		return m.Reload()
	}
	cmd := exec.Command(m.Bin, "-d", m.WorkDir, "-f", m.configPath())
	hideWindow(cmd)
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		m.mu.Unlock()
		return err
	}
	m.cmd = cmd
	m.exited = make(chan struct{})
	exited := m.exited
	m.mu.Unlock()

	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			level := "info"
			if i := strings.Index(line, "level="); i >= 0 {
				level = strings.Fields(line[i+6:])[0]
			}
			if level == "error" || level == "fatal" {
				m.mu.Lock()
				m.lastErr = line
				m.mu.Unlock()
			}
			if m.Logf != nil {
				m.Logf(level, line)
			}
		}
	}()
	go func() {
		cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
		}
		m.mu.Unlock()
		close(exited)
	}()

	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			m.mu.Lock()
			e := m.lastErr
			m.mu.Unlock()
			return fmt.Errorf("движок завершился при запуске: %s", e)
		default:
		}
		if _, err := m.Version(); err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	m.Stop()
	return errors.New("движок не ответил за 30 секунд")
}

// Exited is closed when the current process exits.
func (m *Mihomo) Exited() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.exited == nil {
		c := make(chan struct{})
		close(c)
		return c
	}
	return m.exited
}

// Apply rewrites the config and hot-reloads it (TUN stays up).
func (m *Mihomo) Apply(conf map[string]any) error {
	if !m.Running() {
		return m.Start(conf)
	}
	if err := m.writeConfig(conf); err != nil {
		return err
	}
	return m.Reload()
}

func (m *Mihomo) Reload() error {
	body, _ := json.Marshal(map[string]string{"path": m.configPath()})
	return m.api(http.MethodPut, "/configs?force=true", body, nil)
}

func (m *Mihomo) Stop() {
	m.mu.Lock()
	cmd := m.cmd
	exited := m.exited
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	// Windows has no SIGTERM for console-less processes. Killing is safe: the
	// wintun adapter (and with it every TUN route) disappears together with
	// the process handle.
	cmd.Process.Kill()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
	}
}

// ---- API ----

var apiClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		Proxy:       nil,
		DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
	},
}

func (m *Mihomo) api(method, path string, body []byte, out any) error {
	req, err := http.NewRequest(method, fmt.Sprintf("http://127.0.0.1:%d%s", m.Port, path), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.Secret)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := apiClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mihomo API %s: %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

func (m *Mihomo) Version() (string, error) {
	var v struct {
		Version string `json:"version"`
	}
	err := m.api(http.MethodGet, "/version", nil, &v)
	return v.Version, err
}

type Connection struct {
	ID       string   `json:"id"`
	Upload   int64    `json:"upload"`
	Download int64    `json:"download"`
	Start    string   `json:"start"`
	Chains   []string `json:"chains"`
	Rule     string   `json:"rule"`
	Payload  string   `json:"rulePayload"`
	Metadata struct {
		Network     string `json:"network"`
		Type        string `json:"type"`
		SourceIP    string `json:"sourceIP"`
		DestIP      string `json:"destinationIP"`
		DestPort    string `json:"destinationPort"`
		Host        string `json:"host"`
		Process     string `json:"process"`
		ProcessPath string `json:"processPath"`
		SniffHost   string `json:"sniffHost"`
	} `json:"metadata"`
}

type Connections struct {
	DownloadTotal int64        `json:"downloadTotal"`
	UploadTotal   int64        `json:"uploadTotal"`
	Connections   []Connection `json:"connections"`
}

func (m *Mihomo) Connections() (*Connections, error) {
	var c Connections
	err := m.api(http.MethodGet, "/connections", nil, &c)
	return &c, err
}

func (m *Mihomo) CloseConnection(id string) error {
	return m.api(http.MethodDelete, "/connections/"+url.PathEscape(id), nil, nil)
}

func (m *Mihomo) CloseAllConnections() error {
	return m.api(http.MethodDelete, "/connections", nil, nil)
}

// Delay measures latency through a proxy.
func (m *Mihomo) Delay(proxy, testURL string, timeout time.Duration) (int, error) {
	var r struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	q := url.Values{"url": {testURL}, "timeout": {fmt.Sprint(timeout.Milliseconds())}}
	err := m.api(http.MethodGet, "/proxies/"+url.PathEscape(proxy)+"/delay?"+q.Encode(), nil, &r)
	if err != nil {
		return 0, err
	}
	return r.Delay, nil
}

// Traffic streams up/down rates (bytes/s) until ctx is done.
func (m *Mihomo) Traffic(ctx context.Context, fn func(up, down int64)) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/traffic", m.Port), nil)
	req.Header.Set("Authorization", "Bearer "+m.Secret)
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	for {
		var t struct{ Up, Down int64 }
		if err := dec.Decode(&t); err != nil {
			return err
		}
		fn(t.Up, t.Down)
	}
}

// DNSQuery asks the engine's resolver (rules and policies applied).
func (m *Mihomo) DNSQuery(name, qtype string) (map[string]any, error) {
	if qtype == "" {
		qtype = "A"
	}
	var out map[string]any
	err := m.api(http.MethodGet, "/dns/query?"+url.Values{"name": {name}, "type": {qtype}}.Encode(), nil, &out)
	return out, err
}
