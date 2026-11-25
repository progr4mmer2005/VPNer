package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"vpner/internal/config"
	"vpner/internal/i18n"
)

// Presets travel as VPNer profiles: one preset is a profile with its name,
// all of them a profile with a list of such profiles. The look of the
// window is not part of a preset.

func presetProfile(p config.Preset, withSecrets bool) (Profile, error) {
	b, err := Export(&config.Config{Connections: p.Connections, Rules: p.Rules, Settings: p.Settings, DNS: p.DNS}, withSecrets)
	if err != nil {
		return Profile{}, err
	}
	var out Profile
	if err := json.Unmarshal(b, &out); err != nil {
		return Profile{}, err
	}
	out.Name, out.Appearance = p.Name, nil
	return out, nil
}

// ExportPreset returns one preset as a file.
func ExportPreset(p config.Preset, withSecrets bool) ([]byte, error) {
	out, err := presetProfile(p, withSecrets)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(out, "", "  ")
}

// ExportPresets returns several presets as one file.
func ExportPresets(list []config.Preset, withSecrets bool) ([]byte, error) {
	all := Profile{VPNer: ProfileVersion}
	for _, p := range list {
		out, err := presetProfile(p, withSecrets)
		if err != nil {
			return nil, err
		}
		out.VPNer = 0
		all.Presets = append(all.Presets, out)
	}
	return json.MarshalIndent(all, "", "  ")
}

// IsPresets reports whether the text is a preset file (one or several).
func IsPresets(data string) bool {
	data = strings.TrimSpace(strings.TrimPrefix(data, bom))
	if !strings.HasPrefix(data, "{") {
		return false
	}
	var probe struct {
		VPNer   *int            `json:"vpner"`
		Name    string          `json:"name"`
		Presets json.RawMessage `json:"presets"`
	}
	if json.Unmarshal([]byte(data), &probe) != nil || probe.VPNer == nil {
		return false
	}
	return probe.Name != "" || len(probe.Presets) > 0
}

// ParsePresets reads a preset file. Every preset gets fresh connection ids,
// like any imported profile.
func ParsePresets(data string) ([]config.Preset, []string, error) {
	data = strings.TrimSpace(strings.TrimPrefix(data, bom))
	var top Profile
	if err := json.Unmarshal([]byte(data), &top); err != nil {
		return nil, nil, fmt.Errorf(i18n.T("importer.profileFileIsDamaged"), err)
	}
	if top.VPNer > ProfileVersion {
		return nil, nil, fmt.Errorf(i18n.T("importer.profileWasCreatedByNewer"), top.VPNer)
	}
	list := top.Presets
	if len(list) == 0 {
		top.Presets = nil
		list = []Profile{top}
	}
	var out []config.Preset
	var notes []string
	for i, p := range list {
		p.VPNer, p.Presets, p.Appearance = top.VPNer, nil, nil
		name := strings.TrimSpace(p.Name)
		if name == "" {
			name = fmt.Sprintf(i18n.T("importer.presetUnnamed"), i+1)
		}
		b, _ := json.Marshal(p)
		res, err := parseProfile(string(b))
		if err != nil {
			return nil, nil, err
		}
		for _, n := range res.Notes {
			notes = append(notes, name+": "+n)
		}
		pr := config.Preset{ID: config.NewID("p"), Name: name, Connections: res.Connections, Rules: res.Rules, DNS: config.DefaultDNS()}
		if pr.Connections == nil {
			pr.Connections = []config.Connection{}
		}
		if pr.Rules == nil {
			pr.Rules = []config.Rule{}
		}
		pr.Settings = config.Default().Settings
		if res.Settings != nil {
			pr.Settings = *res.Settings
		}
		if res.DNS != nil {
			pr.DNS = *res.DNS
		}
		out = append(out, pr)
	}
	if len(out) == 0 {
		return nil, nil, errors.New(i18n.T("importer.noPresets"))
	}
	return out, notes, nil
}

// bom is the byte order mark some editors put at the start of a file.
const bom = "\uFEFF"
