//go:build windows

// VPNer: routes traffic of different apps, sites and domains through
// different VPNs at once, each VPN isolated so they cannot conflict or leak.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/systray"

	"vpner/internal/app"
	"vpner/internal/firewall"
	"vpner/internal/web"
	"vpner/internal/winutil"
)

var version = "0.1.0"

type uiInfo struct {
	Port  int    `json:"port"`
	Token string `json:"token"`
}

func dataDir() string {
	if d := os.Getenv("VPNER_DATA"); d != "" {
		return d
	}
	exe, _ := os.Executable()
	// portable mode: a "data" folder next to the executable
	if st, err := os.Stat(filepath.Join(filepath.Dir(exe), "data")); err == nil && st.IsDir() {
		return filepath.Join(filepath.Dir(exe), "data")
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "VPNer")
}

func fatal(msg string) {
	if !winutil.AttachParentConsole() {
		winutil.MessageBox("VPNer", msg, true)
	} else {
		fmt.Fprintln(os.Stderr, "VPNer:", msg)
	}
	os.Exit(1)
}

func main() {
	args := os.Args[1:]
	cmd := ""
	tray := false
	for _, a := range args {
		switch a {
		case "--tray":
			tray = true
		default:
			if !strings.HasPrefix(a, "-") && cmd == "" {
				cmd = a
			}
		}
	}
	switch cmd {
	case "version":
		winutil.AttachParentConsole()
		fmt.Println("VPNer", version)
		return
	case "help", "/?":
		winutil.AttachParentConsole()
		fmt.Println("vpner.exe            запустить программу (окно + значок в трее)\nvpner.exe --tray     запустить свёрнутой в трей\nvpner.exe restore    аварийно восстановить сеть (снять kill-switch)\nvpner.exe version")
		return
	}

	// VPNER_DEV=1 skips elevation for development (TUN and the firewall kill
	// switch will not work without administrator rights).
	if !winutil.IsAdmin() && os.Getenv("VPNER_DEV") != "1" {
		if err := winutil.RelaunchElevated(args); err != nil {
			fatal("Нужны права администратора (для перехвата трафика и защиты от утечек).\n" + err.Error())
		}
		return
	}

	dir := dataDir()
	if cmd == "restore" {
		winutil.AttachParentConsole()
		ks := &firewall.KillSwitch{StateDir: dir}
		if err := ks.Disable(); err != nil {
			fatal(err.Error())
		}
		fmt.Println("Сеть восстановлена: kill-switch снят.")
		return
	}

	uiFile := filepath.Join(dir, "ui.json")
	first, release := winutil.SingleInstance("VPNerSingleInstance")
	if !first {
		// Already running: just show its window.
		if b, err := os.ReadFile(uiFile); err == nil {
			var ui uiInfo
			if json.Unmarshal(b, &ui) == nil {
				winutil.OpenAppWindow(fmt.Sprintf("http://127.0.0.1:%d/#%s", ui.Port, ui.Token), filepath.Join(dir, "ui-profile"))
			}
		}
		return
	}
	defer release()

	a, err := app.New(dir)
	if err != nil {
		fatal(err.Error())
	}
	a.Log.Infof("app", "VPNer %s запущен, данные: %s", version, dir)
	cfg := a.Config()
	if a.KillSwitch().Active() && !cfg.Settings.StartOnLaunch {
		a.KillSwitch().Disable()
		a.Log.Warnf("app", "kill-switch остался после аварийного завершения — снят")
	}

	tok := make([]byte, 24)
	rand.Read(tok)
	srv := &web.Server{App: a, Token: hex.EncodeToString(tok)}
	if err := srv.Start(cfg.Settings.UIPort); err != nil {
		fatal("Не удалось запустить интерфейс: " + err.Error())
	}
	ui, _ := json.Marshal(uiInfo{Port: srv.Port, Token: srv.Token})
	os.WriteFile(uiFile, ui, 0o600)

	var quitOnce sync.Once
	quit := func() {
		quitOnce.Do(func() {
			a.Log.Infof("app", "выход")
			a.Shutdown()
			winutil.CloseAppWindows(winutil.AppWindowTitle)
			srv.Close()
			os.Remove(uiFile)
			systray.Quit()
		})
	}
	srv.OnQuit = quit
	openUI := func() { winutil.OpenAppWindow(srv.URL(), filepath.Join(dir, "ui-profile")) }
	// A VPN asking for input or waiting for a login confirmation must not
	// wait unseen: notify and bring the window up.
	a.OnAttention = func(id, name, text string) {
		winutil.Notify("VPNer — "+name, "Подключение "+text)
		if srv.Clients() == 0 {
			openUI()
		}
	}

	if cfg.Settings.StartOnLaunch {
		go func() {
			if err := a.Start(); err != nil {
				a.Log.Errorf("app", "запуск маршрутизации: %v", err)
			}
		}()
	}
	if !tray {
		openUI()
	}

	systray.Run(func() {
		systray.SetIcon(winutil.Icon("off"))
		systray.SetTitle("VPNer")
		systray.SetTooltip("VPNer")
		mOpen := systray.AddMenuItem("Открыть VPNer", "")
		mToggle := systray.AddMenuItem("Включить маршрутизацию", "")
		systray.AddSeparator()
		mRestore := systray.AddMenuItem("Аварийно восстановить сеть", "Выключить всё и снять kill-switch")
		mQuit := systray.AddMenuItem("Выход", "")
		systray.SetOnTapped(openUI)

		update := func() {
			s := a.Snapshot()
			icon, tip := "off", "VPNer — выключен"
			if s.Running {
				icon, tip = "on", "VPNer — маршрутизация включена"
				for _, c := range s.Connections {
					switch c.State {
					case "down", "failed":
						icon, tip = "warn", "VPNer — есть проблемы с подключениями"
					case "auth", "confirm", "queued":
						if icon != "warn" {
							icon, tip = "warn", "VPNer — подключения ждут подтверждения входа"
						}
					}
				}
				mToggle.SetTitle("Выключить маршрутизацию")
			} else {
				mToggle.SetTitle("Включить маршрутизацию")
			}
			if s.Starting {
				icon, tip = "warn", "VPNer — запуск…"
			}
			systray.SetIcon(winutil.Icon(icon))
			systray.SetTooltip(tip)
		}
		ch, _ := a.Subscribe()
		go func() {
			update()
			t := time.NewTicker(5 * time.Second)
			for {
				select {
				case <-ch:
				case <-t.C:
				}
				update()
			}
		}()
		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					openUI()
				case <-mToggle.ClickedCh:
					if a.Running() {
						go a.Stop()
					} else {
						go a.Start()
					}
				case <-mRestore.ClickedCh:
					go a.EmergencyRestore()
				case <-mQuit.ClickedCh:
					// With VPNs on, confirm in the window first.
					if a.AskQuit() {
						openUI()
						continue
					}
					quit()
					return
				}
			}
		}()
	}, func() {})
	quit()
}
