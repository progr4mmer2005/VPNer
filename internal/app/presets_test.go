package app

import (
	"os"
	"testing"

	"vpner/internal/config"
)

const testLink = "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?security=reality&sni=a.example&pbk=PUBKEY&sid=abcd&type=tcp#x"

func presetApp(t *testing.T) *App {
	t.Helper()
	// the log file stays open, so not t.TempDir (it could not be removed)
	dir, err := os.MkdirTemp("", "vpner-presets-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) }) // best effort
	a, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := a.Config()
	cfg.Connections = []config.Connection{{ID: "c1", Name: "Server", Type: "link", Enabled: true,
		Params: map[string]string{}, Secrets: map[string]string{"link": testLink}}}
	cfg.Rules = []config.Rule{{ID: "r1", Enabled: true, Kind: config.RuleDomainSuffix, Values: []string{"example.com"}, Target: "c1"}}
	cfg.PresetName = "Main"
	if err := a.commit(cfg); err != nil {
		t.Fatal(err)
	}
	return a
}

func names(a *App) (out []string) {
	for _, p := range a.Presets() {
		n := p.Name
		if p.Active {
			n = "*" + n
		}
		out = append(out, n)
	}
	return out
}

// Presets are made, switched, renamed and deleted; the running one cannot
// be deleted and names stay unique.
func TestPresets(t *testing.T) {
	a := presetApp(t)
	if got := a.Presets(); len(got) != 1 || !got[0].Active || got[0].Connections != 1 || got[0].Rules != 1 {
		t.Fatalf("start: %+v", got)
	}
	empty, err := a.NewPreset("Empty", false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := a.Config(); len(cfg.Connections) != 0 || len(cfg.Rules) != 0 || cfg.PresetName != "Empty" {
		t.Fatalf("empty preset runs: %+v", cfg)
	}
	if _, err := a.NewPreset("empty", true); err == nil {
		t.Error("taken name (case aside) accepted")
	}
	if err := a.DeletePreset(empty); err == nil {
		t.Error("running preset deleted")
	}
	// back to the first one: its connection, rule and secret are there
	var main string
	for _, p := range a.Presets() {
		if !p.Active {
			main = p.ID
		}
	}
	if err := a.SwitchPreset(main); err != nil {
		t.Fatal(err)
	}
	cfg := a.Config()
	if len(cfg.Connections) != 1 || cfg.Connections[0].S("link") != testLink || len(cfg.Rules) != 1 {
		t.Fatalf("first preset lost something: %+v", cfg)
	}
	if err := a.RenamePreset(empty, "Main"); err == nil && cfg.PresetName == "Main" {
		t.Error("rename to the name of another preset accepted")
	}
	if err := a.RenamePreset(empty, "Spare"); err != nil {
		t.Fatal(err)
	}
	if err := a.DeletePreset(empty); err != nil {
		t.Fatal(err)
	}
	if got := a.Presets(); len(got) != 1 {
		t.Fatalf("after delete: %v", names(a))
	}
}

// The waiting presets and their secrets are kept on disk.
func TestPresetsSaved(t *testing.T) {
	a := presetApp(t)
	if _, err := a.NewPreset("Copy", true); err != nil {
		t.Fatal(err)
	}
	b, err := New(a.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := b.Config()
	if len(cfg.Presets) != 1 || len(cfg.Presets[0].Connections) != 1 || cfg.Presets[0].Connections[0].S("link") != testLink {
		t.Fatalf("waiting preset not kept: %+v", cfg.Presets)
	}
	if cfg.PresetName != "Copy" || cfg.Connections[0].S("link") != testLink {
		t.Fatalf("running preset not kept: %+v", cfg)
	}
}

// Importing a file of presets: free names are added, taken ones are
// replaced, renamed (old or new) or skipped as decided.
func TestImportPresets(t *testing.T) {
	src := presetApp(t)
	if _, err := src.NewPreset("Home", true); err != nil {
		t.Fatal(err)
	}
	if _, err := src.NewPreset("Work", false); err != nil {
		t.Fatal(err)
	}
	file, _, err := src.ExportPreset("", true) // Main, Home, Work in some order
	if err != nil {
		t.Fatal(err)
	}

	dst := presetApp(t) // has "Main" running
	if _, err := dst.NewPreset("Home", false); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.NewPreset("Work", false); err != nil {
		t.Fatal(err)
	}
	prev, err := dst.PreviewPresets(string(file))
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Items) != 3 {
		t.Fatalf("preview: %+v", prev)
	}
	var decisions []PresetDecision
	for i, it := range prev.Items {
		if !it.Conflict {
			t.Fatalf("%s: no conflict", it.Name)
		}
		switch it.Name {
		case "Main":
			decisions = append(decisions, PresetDecision{Index: i, Action: "renameNew", Name: "Main from file"})
		case "Home":
			decisions = append(decisions, PresetDecision{Index: i, Action: "renameOld", OldName: "Old home"})
		case "Work":
			if !it.ActiveTaken {
				t.Error("Work runs in dst but is not marked")
			}
			decisions = append(decisions, PresetDecision{Index: i, Action: "skip"})
		}
	}
	n, err := dst.ImportPresets(string(file), decisions)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("added %d, want 2", n)
	}
	got := map[string]PresetInfo{}
	for _, p := range dst.Presets() {
		got[p.Name] = p
	}
	for _, want := range []string{"Main", "Main from file", "Old home", "Home", "Work"} {
		if _, ok := got[want]; !ok {
			t.Errorf("no preset %q: %v", want, names(dst))
		}
	}
	if got["Home"].Connections != 1 || got["Old home"].Connections != 0 || !got["Work"].Active {
		t.Errorf("wrong contents: %+v", got)
	}

	// replace the running one: it is applied at once
	prev, _ = dst.PreviewPresets(string(file))
	decisions = nil
	for i, it := range prev.Items {
		a := "skip"
		if it.Name == "Home" {
			a = "replace"
		}
		decisions = append(decisions, PresetDecision{Index: i, Action: a})
	}
	if _, err := dst.ImportPresets(string(file), decisions); err != nil {
		t.Fatal(err)
	}
	for _, p := range dst.Presets() {
		if p.Name == "Home" && p.Connections != 1 {
			t.Errorf("Home not replaced: %+v", p)
		}
	}
}

// The settings of the program itself stay when another preset runs.
func TestKeepAppSettings(t *testing.T) {
	s := config.Settings{Language: "en", UIPort: 1, Autostart: false, KillSwitch: true}
	config.KeepAppSettings(&s, config.Settings{Language: "ru", UIPort: 7, Autostart: true, StartOnLaunch: true})
	if s.Language != "ru" || s.UIPort != 7 || !s.Autostart || !s.StartOnLaunch || !s.KillSwitch {
		t.Fatalf("%+v", s)
	}
}
