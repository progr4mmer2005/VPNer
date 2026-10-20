//go:build windows

// vpner-setup installs VPNer. The wizard is the VPNer interface itself in
// setup mode, so the theme chosen there is what the program looks like.
package main

import (
	"compress/gzip"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"vpner/internal/config"
	"vpner/internal/install"
	"vpner/internal/web"
	"vpner/internal/winutil"
)

var version = "0.1.0"

// payload/vpner.exe.gz is put there by build.ps1 before this is built.
//
//go:embed all:payload
var payload embed.FS

const windowTitle = "Установка VPNer"

type step struct {
	Text string `json:"text"`
	Done bool   `json:"done"`
}

type setup struct {
	mu         sync.Mutex
	opts       install.Options
	appearance json.RawMessage
	steps      []step
	installing bool
	done       bool
	err        string
	lastPing   time.Time
	quit       chan struct{}
	quitOnce   sync.Once
}

func (st *setup) exit() { st.quitOnce.Do(func() { close(st.quit) }) }

func store() *config.Store {
	return &config.Store{Path: filepath.Join(install.DataDir(), "config.json")}
}

func main() {
	if !winutil.IsAdmin() {
		if err := winutil.RelaunchElevated(os.Args[1:]); err != nil {
			winutil.MessageBox(windowTitle, "Для установки нужны права администратора.\n"+err.Error(), true)
		}
		return
	}
	first, release := winutil.SingleInstance("VPNerSetup")
	if !first {
		winutil.FocusAppWindow(windowTitle)
		return
	}
	defer release()

	st := &setup{quit: make(chan struct{}), lastPing: time.Now(),
		opts: install.Options{Dir: install.DefaultDir(), Desktop: true, StartMenu: true, Launch: true, Autostart: winutil.AutostartEnabled()}}
	if cfg, err := store().Load(); err == nil {
		st.appearance = cfg.Appearance // an update keeps the current look as the default choice
	}

	tok := make([]byte, 24)
	rand.Read(tok)
	token := hex.EncodeToString(tok)
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		winutil.MessageBox(windowTitle, err.Error(), true)
		return
	}
	mux := http.NewServeMux()
	st.routes(mux)
	go http.Serve(l, web.Guard(token, mux))

	profile, _ := os.MkdirTemp("", "vpner-setup-ui")
	url := fmt.Sprintf("http://127.0.0.1:%d/#%s", l.Addr().(*net.TCPAddr).Port, token)
	cmd, err := winutil.StartAppWindow(url, profile, 940, 720)
	if err != nil {
		winutil.MessageBox(windowTitle, "Для установщика нужен Microsoft Edge (он есть в Windows 10 и 11).\n"+err.Error(), true)
		return
	}
	opened := time.Now()
	go func() {
		cmd.Wait()
		// the window was closed (a launcher that hands over at once is
		// covered by the heartbeat below)
		if time.Since(opened) > 5*time.Second {
			st.exitUnlessInstalling()
		}
	}()
	go func() {
		for range time.Tick(2 * time.Second) {
			st.mu.Lock()
			idle := time.Since(st.lastPing) > 20*time.Second && !st.installing
			st.mu.Unlock()
			if idle {
				st.exit()
				return
			}
		}
	}()
	<-st.quit
	winutil.CloseAppWindows(windowTitle)
	time.Sleep(time.Second)
	os.RemoveAll(profile)
}

func (st *setup) exitUnlessInstalling() {
	for {
		st.mu.Lock()
		busy := st.installing
		st.mu.Unlock()
		if !busy {
			st.exit()
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
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

func (st *setup) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		look := st.appearance
		st.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", web.CSP)
		w.Write(web.Page(look, "window.VPNER_SETUP = true;"))
	})
	// what the interface needs to start (an empty program, the saved look)
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		writeJSON(w, map[string]any{"connections": []any{}, "rules": []any{}, "settings": map[string]any{"finalTarget": "DIRECT"},
			"dns": map[string]any{"servers": []any{}, "rules": []any{}, "default": []any{}}, "appearance": st.appearance})
	})
	mux.HandleFunc("GET /api/providers", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, []any{}) })
	mux.HandleFunc("GET /api/info", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]string{"version": version}) })
	mux.HandleFunc("GET /api/logs", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, []any{}) })
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
		if err != nil || !json.Valid(b) {
			writeErr(w, fmt.Errorf("настройки оформления повреждены"))
			return
		}
		st.mu.Lock()
		st.appearance = b
		st.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /api/setup", func(w http.ResponseWriter, r *http.Request) {
		_, installed := install.Installed()
		st.mu.Lock()
		defer st.mu.Unlock()
		writeJSON(w, map[string]any{"version": version, "installed": installed, "running": install.Running(), "opts": st.opts})
	})
	mux.HandleFunc("POST /api/setup/ping", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		st.lastPing = time.Now()
		st.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/setup/install", func(w http.ResponseWriter, r *http.Request) {
		var o install.Options
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&o); err != nil {
			writeErr(w, err)
			return
		}
		st.mu.Lock()
		if st.installing {
			st.mu.Unlock()
			writeErr(w, fmt.Errorf("установка уже идёт"))
			return
		}
		st.opts, st.installing, st.done, st.err, st.steps = o, true, false, "", nil
		st.mu.Unlock()
		go st.run(o)
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/setup/status", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		writeJSON(w, map[string]any{"steps": st.steps, "installing": st.installing, "done": st.done, "error": st.err})
	})
	mux.HandleFunc("POST /api/setup/finish", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Launch bool `json:"launch"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req)
		st.mu.Lock()
		done, dir := st.done, st.opts.Dir
		st.mu.Unlock()
		if done && req.Launch {
			exec.Command(filepath.Join(dir, install.ExeName)).Start()
		}
		writeJSON(w, map[string]bool{"ok": true})
		go func() { time.Sleep(200 * time.Millisecond); st.exit() }()
	})
}

func (st *setup) step(text string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range st.steps {
		st.steps[i].Done = true
	}
	st.steps = append(st.steps, step{Text: text})
}

func unpack() ([]byte, error) {
	f, err := payload.Open("payload/" + install.ExeName + ".gz")
	if err != nil {
		return nil, errors.New("в установщике нет программы (собран без неё)")
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

func (st *setup) run(o install.Options) {
	exe, err := unpack()
	if err == nil {
		err = install.Install(exe, version, o, st.step)
	}
	if err == nil {
		st.step("сохраняю выбранное оформление")
		err = st.saveLook(o)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	for i := range st.steps {
		st.steps[i].Done = err == nil || i < len(st.steps)-1
	}
	st.installing = false
	if err != nil {
		st.err = err.Error()
		return
	}
	st.done = true
}

// saveLook writes the look chosen in the wizard (and the autostart choice)
// into the settings the program reads.
func (st *setup) saveLook(o install.Options) error {
	s := store()
	cfg, err := s.Load()
	if err != nil {
		return err
	}
	st.mu.Lock()
	if len(st.appearance) > 0 {
		cfg.Appearance = append(json.RawMessage(nil), st.appearance...)
	}
	st.mu.Unlock()
	cfg.Settings.Autostart = o.Autostart
	os.MkdirAll(filepath.Dir(s.Path), 0o700)
	return s.Save(cfg)
}
