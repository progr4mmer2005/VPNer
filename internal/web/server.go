//go:build windows

// Package web serves the local UI and its JSON API on 127.0.0.1.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"vpner/internal/app"
	"vpner/internal/config"
	"vpner/internal/deps"
	"vpner/internal/providers"
	"vpner/internal/winutil"
)

//go:embed index.html
var indexHTML []byte

type Server struct {
	App   *app.App
	Token string
	Port  int
	// OnQuit is called when the user chooses "Выход" in the UI.
	OnQuit  func()
	srv     *http.Server
	clients atomic.Int32 // open UI windows (event streams)
}

// Clients reports how many UI windows are currently connected.
func (s *Server) Clients() int { return int(s.clients.Load()) }

func (s *Server) URL() string {
	return fmt.Sprintf("http://127.0.0.1:%d/#%s", s.Port, s.Token)
}

func (s *Server) Start(port int) error {
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil && port != 0 {
		l, err = net.Listen("tcp4", "127.0.0.1:0")
	}
	if err != nil {
		return err
	}
	s.Port = l.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	s.routes(mux)
	s.srv = &http.Server{Handler: s.guard(mux), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(l)
	return nil
}

func (s *Server) Close() {
	if s.srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s.srv.Shutdown(ctx)
	}
}

// guard: only loopback Host headers (DNS-rebinding protection) and a token
// for every API call (CSRF protection).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			tok := r.Header.Get("X-Token")
			if tok == "" {
				tok = r.URL.Query().Get("token")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 16<<20)).Decode(v)
}

// connDTO is a connection as the UI sees it: secret values are never sent,
// only which of them are set.
type connDTO struct {
	config.Connection
	SecretSet map[string]bool `json:"secretSet"`
}

// page is the UI with the saved theme already in it, so the window opens
// in its look instead of flashing the standard one first.
func (s *Server) page() []byte {
	var a struct {
		Look *struct {
			T   string `json:"t"`
			M   string `json:"m"`
			CSS string `json:"css"`
		} `json:"look"`
	}
	look := []byte("null")
	if raw := s.App.Config().Appearance; len(raw) > 0 && json.Unmarshal(raw, &a) == nil && a.Look != nil {
		if b, err := json.Marshal(a.Look); err == nil { // also escapes <, > and &
			look = b
		}
	}
	return bytes.Replace(indexHTML, []byte("<!--vpner-look-->"), append(append([]byte("<script>window.VPNER_LOOK = "), look...), []byte(";</script>")...), 1)
}

func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Write(s.page())
	})

	mux.HandleFunc("GET /api/state", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, s.App.Snapshot()) })

	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		cfg := s.App.Config()
		out := struct {
			Connections []connDTO       `json:"connections"`
			Rules       []config.Rule   `json:"rules"`
			Settings    config.Settings `json:"settings"`
			DNS         config.DNS      `json:"dns"`
			Appearance  json.RawMessage `json:"appearance,omitempty"`
			DataDir     string          `json:"dataDir"`
		}{Rules: cfg.Rules, Settings: cfg.Settings, DNS: cfg.DNS, Appearance: cfg.Appearance, DataDir: s.App.DataDir}
		for _, c := range cfg.Connections {
			d := connDTO{Connection: c, SecretSet: map[string]bool{}}
			for k, v := range c.Secrets {
				d.SecretSet[k] = v != ""
			}
			d.Secrets = nil
			out.Connections = append(out.Connections, d)
		}
		writeJSON(w, out)
	})

	mux.HandleFunc("GET /api/providers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, app.Providers()) })
	mux.HandleFunc("GET /api/interfaces", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, app.Interfaces()) })
	mux.HandleFunc("GET /api/processes", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, winutil.Processes()) })

	mux.HandleFunc("POST /api/connections", func(w http.ResponseWriter, r *http.Request) {
		var c config.Connection
		if err := readJSON(r, &c); err != nil {
			writeErr(w, err)
			return
		}
		id, err := s.App.SaveConnection(c)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"id": id})
	})
	mux.HandleFunc("DELETE /api/connections/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := s.App.DeleteConnection(r.PathValue("id")); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/connections/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var err error
		switch r.PathValue("action") {
		case "connect":
			go func() {
				if err := s.App.Connect(id); err != nil {
					s.App.Log.Errorf(id, "%v", err)
				}
			}()
		case "disconnect":
			err = s.App.Disconnect(id)
		case "answer":
			var b struct{ Text string }
			if err = readJSON(r, &b); err == nil {
				err = s.App.Answer(id, b.Text)
			}
		case "console":
			err = s.App.OpenConsole(id)
		default:
			err = fmt.Errorf("неизвестное действие")
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /api/connections/{id}/upload", func(w http.ResponseWriter, r *http.Request) {
		if err := s.App.VMUpload(r.PathValue("id"), r.URL.Query().Get("name"), r.Body); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/hyperv", func(w http.ResponseWriter, r *http.Request) {
		msg := app.HyperVStatus()
		writeJSON(w, map[string]any{"ok": msg == "", "detail": msg})
	})
	mux.HandleFunc("POST /api/hyperv/enable", func(w http.ResponseWriter, r *http.Request) {
		out, err := app.EnableHyperV()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"output": out})
	})

	// Import anything: one key/config, a list of links, Clash YAML, a VPNer
	// profile or a subscription URL. dry=1 returns a summary only.
	mux.HandleFunc("POST /api/import", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Filename     string `json:"filename"`
			Data         string `json:"data"`
			Subscription string `json:"subscription"`
			Dry          bool   `json:"dry"`
			app.ImportOptions
		}
		if err := readJSON(r, &b); err != nil {
			writeErr(w, err)
			return
		}
		if b.Subscription == "" && (app.IsSubscriptionLink(b.Data) || strings.HasPrefix(strings.ToLower(strings.TrimSpace(b.Data)), "happ://")) {
			b.Subscription = b.Data
		}
		if b.Subscription != "" {
			body, err := s.App.FetchSubscription(b.Subscription)
			if err != nil {
				writeErr(w, err)
				return
			}
			b.Data, b.Filename = body, "subscription"
		}
		out, err := s.App.ImportData(b.Filename, b.Data, b.Dry, b.ImportOptions)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, out)
	})

	// Export into a file chosen in the standard Windows "Save as" dialog
	// (instead of a browser download).
	mux.HandleFunc("POST /api/export/save", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Secrets bool `json:"secrets"`
		}
		if err := readJSON(r, &req); err != nil {
			writeErr(w, err)
			return
		}
		data, err := s.App.Export(req.Secrets)
		if err != nil {
			writeErr(w, err)
			return
		}
		name := "vpner-profile-" + time.Now().Format("2006-01-02") + ".json"
		path, ok, err := winutil.SaveFileDialog("Сохранить профиль VPNer", name, "Профиль VPNer", "json")
		if err != nil {
			writeErr(w, err)
			return
		}
		if !ok {
			writeJSON(w, map[string]any{"canceled": true})
			return
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"path": path})
	})
	// The clipboard for the window's own "Вставить" menu item (the browser
	// would ask for a permission).
	mux.HandleFunc("GET /api/clipboard", func(w http.ResponseWriter, r *http.Request) {
		text, err := winutil.ClipboardText()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"text": text})
	})

	mux.HandleFunc("PUT /api/appearance", func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(io.LimitReader(r.Body, 512<<10))
		if err != nil {
			writeErr(w, err)
			return
		}
		if err := s.App.SaveAppearance(b); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("PUT /api/rules", func(w http.ResponseWriter, r *http.Request) {
		var rules []config.Rule
		if err := readJSON(r, &rules); err != nil {
			writeErr(w, err)
			return
		}
		if err := s.App.SaveRules(rules); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("PUT /api/dns", func(w http.ResponseWriter, r *http.Request) {
		var d config.DNS
		if err := readJSON(r, &d); err != nil {
			writeErr(w, err)
			return
		}
		if err := s.App.SaveDNS(d); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/dns/query", func(w http.ResponseWriter, r *http.Request) {
		out, err := s.App.DNSQuery(r.URL.Query().Get("name"), r.URL.Query().Get("type"))
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("PUT /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var st config.Settings
		if err := readJSON(r, &st); err != nil {
			writeErr(w, err)
			return
		}
		if err := s.App.SaveSettings(st); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /api/start", func(w http.ResponseWriter, r *http.Request) {
		go s.App.Start()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/stop", func(w http.ResponseWriter, r *http.Request) {
		if err := s.App.Stop(); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/restore", func(w http.ResponseWriter, r *http.Request) {
		if err := s.App.EmergencyRestore(); err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	// Quit for real (the user confirmed, or nothing was running).
	mux.HandleFunc("POST /api/quit", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
		if s.OnQuit != nil {
			go s.OnQuit()
		}
	})
	mux.HandleFunc("POST /api/quit/cancel", func(w http.ResponseWriter, r *http.Request) {
		s.App.CancelQuit()
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /api/live", func(w http.ResponseWriter, r *http.Request) {
		v, err := s.App.Live()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, v)
	})
	mux.HandleFunc("DELETE /api/live/{id}", func(w http.ResponseWriter, r *http.Request) {
		if m := s.App.Engine(); m != nil {
			if id := r.PathValue("id"); id == "all" {
				m.CloseAllConnections()
			} else {
				m.CloseConnection(id)
			}
		}
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("POST /api/leaktest", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		rep, err := s.App.LeakTest(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("GET /api/route", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.App.CheckRoute(r.URL.Query().Get("host"), r.URL.Query().Get("process")))
	})

	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) {
		since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
		writeJSON(w, s.App.Log.Since(since))
	})

	mux.HandleFunc("GET /api/wsl", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, deps.CheckWSL()) })
	mux.HandleFunc("POST /api/wsl/install", func(w http.ResponseWriter, r *http.Request) {
		out, err := deps.InstallWSL()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]string{"output": out})
	})
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"admin": winutil.IsAdmin(), "dataDir": s.App.DataDir, "mihomo": deps.MihomoVersion,
			"wslPackages": providers.AllPackages(),
		})
	})

	// Server-sent events: state changes and log lines.
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no streaming", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		s.clients.Add(1)
		defer s.clients.Add(-1)
		ch, unsub := s.App.Subscribe()
		defer unsub()
		logs, unsubLogs := s.App.Log.Subscribe()
		defer unsubLogs()
		send := func(event string, v any) bool {
			b, _ := json.Marshal(v)
			_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
			fl.Flush()
			return err == nil
		}
		if !send("state", s.App.Snapshot()) {
			return
		}
		tick := time.NewTicker(20 * time.Second)
		defer tick.Stop()
		var pending bool
		throttle := time.NewTimer(time.Hour)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ch:
				if !pending {
					pending = true
					throttle.Reset(150 * time.Millisecond)
				}
			case <-throttle.C:
				pending = false
				if !send("state", s.App.Snapshot()) {
					return
				}
			case e := <-logs:
				if !send("log", e) {
					return
				}
			case <-tick.C:
				if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
					return
				}
				fl.Flush()
			}
		}
	})
}
