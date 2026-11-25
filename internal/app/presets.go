package app

import (
	"errors"
	"fmt"
	"strings"

	"vpner/internal/config"
	"vpner/internal/i18n"
	"vpner/internal/importer"
)

// Presets are whole VPNer setups (connections, rules, DNS, routing
// settings) kept under names; one of them is active and lives in the
// config as usual, the others wait in cfg.Presets. Switching stops the
// connections the new preset does not have and applies it like any saved
// change. VMs and users on servers stay: another preset may use them.

// PresetInfo is a preset as the window lists it.
type PresetInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Active      bool   `json:"active"`
	Connections int    `json:"connections"`
	Rules       int    `json:"rules"`
}

func activeName(cfg *config.Config) string {
	if n := strings.TrimSpace(cfg.PresetName); n != "" {
		return n
	}
	return i18n.T("app.presetMain")
}

// ensureActiveID gives the active preset an id the first time it is needed.
func ensureActiveID(cfg *config.Config) {
	if cfg.PresetID == "" {
		cfg.PresetID = config.NewID("p")
	}
	if strings.TrimSpace(cfg.PresetName) == "" {
		cfg.PresetName = i18n.T("app.presetMain")
	}
}

// activePreset is the running setup as a preset.
func activePreset(cfg *config.Config) config.Preset {
	ensureActiveID(cfg)
	return config.Preset{ID: cfg.PresetID, Name: cfg.PresetName, Connections: cfg.Connections, Rules: cfg.Rules, Settings: cfg.Settings, DNS: cfg.DNS}
}

// putActive makes p the running setup; the settings of the program itself
// stay.
func putActive(cfg *config.Config, p config.Preset) {
	s := p.Settings
	config.KeepAppSettings(&s, cfg.Settings)
	cfg.Connections, cfg.Rules, cfg.Settings, cfg.DNS = p.Connections, p.Rules, s, p.DNS
	cfg.PresetID, cfg.PresetName = p.ID, p.Name
	if cfg.Connections == nil {
		cfg.Connections = []config.Connection{}
	}
	if cfg.Rules == nil {
		cfg.Rules = []config.Rule{}
	}
}

// presetCurrent stands for the running preset before it has an id.
const presetCurrent = "current"

// Presets lists the presets, the active one first.
func (a *App) Presets() []PresetInfo {
	cfg := a.Config()
	id := cfg.PresetID
	if id == "" {
		id = presetCurrent
	}
	out := []PresetInfo{{ID: id, Name: activeName(cfg), Active: true, Connections: len(cfg.Connections), Rules: len(cfg.Rules)}}
	for _, p := range cfg.Presets {
		out = append(out, PresetInfo{ID: p.ID, Name: p.Name, Connections: len(p.Connections), Rules: len(p.Rules)})
	}
	return out
}

// presetNameTaken: names are unique, case aside. except is the id allowed
// to have it (the preset being renamed).
func presetNameTaken(cfg *config.Config, name, except string) bool {
	same := func(n string) bool { return strings.EqualFold(strings.TrimSpace(n), strings.TrimSpace(name)) }
	if cfg.PresetID != except && same(activeName(cfg)) {
		return true
	}
	for _, p := range cfg.Presets {
		if p.ID != except && same(p.Name) {
			return true
		}
	}
	return false
}

// uniquePresetName adds " (2)", " (3)"... until the name is free.
func uniquePresetName(cfg *config.Config, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = i18n.T("app.presetNew")
	}
	if !presetNameTaken(cfg, name, "") {
		return name
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s (%d)", name, i); !presetNameTaken(cfg, n, "") {
			return n
		}
	}
}

func checkPresetName(cfg *config.Config, name, except string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New(i18n.T("app.presetNameEmpty"))
	}
	if presetNameTaken(cfg, name, except) {
		return "", fmt.Errorf(i18n.T("app.presetNameTaken"), name)
	}
	return name, nil
}

// switchTo makes p the running setup of cfg (the old one becomes a waiting
// preset unless dropOld) and commits. Connections p does not have are
// stopped first.
func (a *App) switchTo(cfg *config.Config, p config.Preset, dropOld bool) error {
	old := activePreset(cfg)
	keep := map[string]bool{}
	for _, c := range p.Connections {
		keep[c.ID] = true
	}
	for _, c := range cfg.Connections {
		if !keep[c.ID] {
			a.disconnect(c.ID, false)
		}
	}
	var rest []config.Preset
	for _, x := range cfg.Presets {
		if x.ID != p.ID {
			rest = append(rest, x)
		}
	}
	if !dropOld {
		rest = append(rest, old)
	}
	cfg.Presets = rest
	putActive(cfg, p)
	return a.commit(cfg)
}

// SwitchPreset makes the preset id the running one.
func (a *App) SwitchPreset(id string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	if id == cfg.PresetID || id == presetCurrent {
		return nil
	}
	for _, p := range cfg.Presets {
		if p.ID == id {
			if err := a.switchTo(cfg, p, false); err != nil {
				return err
			}
			a.Log.Infof("app", i18n.T("app.presetSwitched"), p.Name)
			return nil
		}
	}
	return errors.New(i18n.T("app.presetNotFound"))
}

// NewPreset makes a preset, a copy of the running one or empty, and
// switches to it.
func (a *App) NewPreset(name string, copyCurrent bool) (string, error) {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	ensureActiveID(cfg)
	name, err := checkPresetName(cfg, name, "")
	if err != nil {
		return "", err
	}
	p := config.Preset{ID: config.NewID("p"), Name: name, Connections: []config.Connection{}, Rules: []config.Rule{}, Settings: config.Default().Settings, DNS: config.DefaultDNS()}
	if copyCurrent {
		cur := cfg.Clone()
		p.Connections, p.Rules, p.Settings, p.DNS = cur.Connections, cur.Rules, cur.Settings, cur.DNS
	}
	if err := a.switchTo(cfg, p, false); err != nil {
		return "", err
	}
	a.Log.Infof("app", i18n.T("app.presetCreated"), name)
	return p.ID, nil
}

// RenamePreset renames a preset, the running one too.
func (a *App) RenamePreset(id, name string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	ensureActiveID(cfg)
	if id == presetCurrent {
		id = cfg.PresetID
	}
	name, err := checkPresetName(cfg, name, id)
	if err != nil {
		return err
	}
	if id == cfg.PresetID {
		cfg.PresetName = name
		return a.commit(cfg)
	}
	for i := range cfg.Presets {
		if cfg.Presets[i].ID == id {
			cfg.Presets[i].Name = name
			return a.commit(cfg)
		}
	}
	return errors.New(i18n.T("app.presetNotFound"))
}

// DeletePreset deletes a waiting preset (not the running one).
func (a *App) DeletePreset(id string) error {
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	if id == cfg.PresetID || id == presetCurrent {
		return errors.New(i18n.T("app.presetDeleteActive"))
	}
	var rest []config.Preset
	var name string
	for _, p := range cfg.Presets {
		if p.ID == id {
			name = p.Name
			continue
		}
		rest = append(rest, p)
	}
	if name == "" {
		return errors.New(i18n.T("app.presetNotFound"))
	}
	cfg.Presets = rest
	if err := a.commit(cfg); err != nil {
		return err
	}
	a.Log.Infof("app", i18n.T("app.presetDeleted"), name)
	return nil
}

// UsedByPresets reports whether a waiting preset has a connection with this
// id: then its VM and its users on servers must stay when the running
// preset deletes or rekeys it.
func usedByPresets(cfg *config.Config, id string) bool {
	for _, p := range cfg.Presets {
		for _, c := range p.Connections {
			if c.ID == id {
				return true
			}
		}
	}
	return false
}

// ExportPreset returns one preset as a file ("" = all of them together).
func (a *App) ExportPreset(id string, withSecrets bool) ([]byte, string, error) {
	cfg := a.Config()
	all := append([]config.Preset{activePreset(cfg)}, cfg.Presets...)
	if id == presetCurrent {
		id = all[0].ID
	}
	if id == "" {
		b, err := importer.ExportPresets(all, withSecrets)
		return b, "", err
	}
	for _, p := range all {
		if p.ID == id {
			b, err := importer.ExportPreset(p, withSecrets)
			return b, p.Name, err
		}
	}
	return nil, "", errors.New(i18n.T("app.presetNotFound"))
}

// PresetImportItem is one preset of a file as the import window shows it.
type PresetImportItem struct {
	Name        string `json:"name"`
	Connections int    `json:"connections"`
	Rules       int    `json:"rules"`
	Conflict    bool   `json:"conflict"`       // a preset with this name exists
	ActiveTaken bool   `json:"activeConflict"` // ...and it is the running one
	Suggest     string `json:"suggest"`        // a free name for a rename
}

type PresetImportPreview struct {
	Items []PresetImportItem `json:"items"`
	Notes []string           `json:"notes,omitempty"`
}

// PresetDecision says what to do with preset Index of the file when its name
// is taken: replace the existing one, rename the existing one (to OldName),
// rename the new one (to Name), or skip it. Presets with a free name are
// added unless skipped.
type PresetDecision struct {
	Index   int    `json:"index"`
	Action  string `json:"action"` // add|replace|renameOld|renameNew|skip
	Name    string `json:"name,omitempty"`
	OldName string `json:"oldName,omitempty"`
}

// PreviewPresets lists the presets of a file and the names already taken.
func (a *App) PreviewPresets(data string) (*PresetImportPreview, error) {
	list, notes, err := importer.ParsePresets(data)
	if err != nil {
		return nil, err
	}
	cfg := a.Config()
	out := &PresetImportPreview{Notes: notes}
	for _, p := range list {
		it := PresetImportItem{Name: p.Name, Connections: len(p.Connections), Rules: len(p.Rules)}
		if presetNameTaken(cfg, p.Name, "") {
			it.Conflict = true
			it.ActiveTaken = strings.EqualFold(activeName(cfg), p.Name)
			it.Suggest = uniquePresetName(cfg, p.Name)
		}
		out.Items = append(out.Items, it)
	}
	return out, nil
}

// presetByName finds a preset by name: -1 is the running one, -2 none.
func presetByName(cfg *config.Config, name string) int {
	if strings.EqualFold(activeName(cfg), strings.TrimSpace(name)) {
		return -1
	}
	for i, p := range cfg.Presets {
		if strings.EqualFold(p.Name, strings.TrimSpace(name)) {
			return i
		}
	}
	return -2
}

// ImportPresets adds the presets of a file as decided. They wait; only a
// preset that replaces the running one is applied at once.
func (a *App) ImportPresets(data string, decisions []PresetDecision) (int, error) {
	list, _, err := importer.ParsePresets(data)
	if err != nil {
		return 0, err
	}
	dec := map[int]PresetDecision{}
	for _, d := range decisions {
		dec[d.Index] = d
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	ensureActiveID(cfg)
	var newActive *config.Preset
	added := 0
	for i, p := range list {
		d, ok := dec[i]
		if !ok {
			d.Action = "add"
		}
		at := presetByName(cfg, p.Name)
		if d.Action == "skip" {
			continue
		}
		if at == -2 {
			cfg.Presets = append(cfg.Presets, p)
			added++
			continue
		}
		switch d.Action {
		case "replace":
			if at == -1 {
				p.ID, p.Name = cfg.PresetID, activeName(cfg)
				cp := p
				newActive = &cp
			} else {
				p.ID, p.Name = cfg.Presets[at].ID, cfg.Presets[at].Name
				cfg.Presets[at] = p
			}
		case "renameOld":
			old := uniquePresetName(cfg, d.OldName)
			if n := strings.TrimSpace(d.OldName); n != "" && !presetNameTaken(cfg, n, "") {
				old = n
			}
			if at == -1 {
				cfg.PresetName = old
			} else {
				cfg.Presets[at].Name = old
			}
			cfg.Presets = append(cfg.Presets, p)
		case "renameNew":
			p.Name = uniquePresetName(cfg, d.Name)
			if n := strings.TrimSpace(d.Name); n != "" && !presetNameTaken(cfg, n, "") {
				p.Name = n
			}
			cfg.Presets = append(cfg.Presets, p)
		default: // a taken name and no decision: keep both
			p.Name = uniquePresetName(cfg, p.Name)
			cfg.Presets = append(cfg.Presets, p)
		}
		added++
	}
	if newActive != nil {
		err = a.switchTo(cfg, *newActive, true)
	} else {
		err = a.commit(cfg)
	}
	if err != nil {
		return 0, err
	}
	a.Log.Infof("app", i18n.T("app.presetsImported"), added)
	return added, nil
}
