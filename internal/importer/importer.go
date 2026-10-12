// Package importer turns pasted text, files and subscriptions into sets of
// connections and rules: a single key or config, a list of share links, a
// whole Clash/mihomo config, or a complete VPNer profile.
package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"vpner/internal/config"
	"vpner/internal/providers"
)

const ProfileVersion = 1

// Profile is the export format of VPNer itself.
type Profile struct {
	VPNer       int                 `json:"vpner"`
	Connections []config.Connection `json:"connections"`
	Rules       []config.Rule       `json:"rules"`
	Settings    *config.Settings    `json:"settings,omitempty"`
	DNS         *config.DNS         `json:"dns,omitempty"`
}

// Result is what an import would add. Connection ids are fresh; rule targets
// already point at them.
type Result struct {
	Kind        string              `json:"kind"` // single|list|clash|profile
	Connections []config.Connection `json:"-"`
	Rules       []config.Rule       `json:"-"`
	FinalTarget string              `json:"-"`
	Settings    *config.Settings    `json:"-"`
	DNS         *config.DNS         `json:"-"`
	Notes       []string            `json:"notes,omitempty"`
}

// Summary is shown to the user before applying.
type Summary struct {
	Kind        string   `json:"kind"`
	Connections []string `json:"connections"`
	Rules       int      `json:"rules"`
	RuleValues  int      `json:"ruleValues"`
	HasFinal    bool     `json:"hasFinal"`
	HasSettings bool     `json:"hasSettings"`
	Notes       []string `json:"notes,omitempty"`
}

func (r *Result) Summary() Summary {
	s := Summary{Kind: r.Kind, Rules: len(r.Rules), HasFinal: r.FinalTarget != "", HasSettings: r.Settings != nil || r.DNS != nil, Notes: r.Notes}
	for _, c := range r.Connections {
		s.Connections = append(s.Connections, c.Name)
	}
	for _, rl := range r.Rules {
		s.RuleValues += len(rl.Values)
	}
	return s
}

// Parse detects the format and builds the result.
func Parse(filename, data string) (*Result, error) {
	data = strings.TrimSpace(strings.TrimPrefix(data, "\uFEFF"))
	if data == "" {
		return nil, errors.New("пусто")
	}
	// VPNer profile
	if strings.HasPrefix(data, "{") {
		var probe map[string]json.RawMessage
		if json.Unmarshal([]byte(data), &probe) == nil {
			if _, ok := probe["vpner"]; ok {
				return parseProfile(data)
			}
		}
	}
	// Clash / mihomo config with a proxies list
	if looksLikeClash(data) {
		return parseClash(data)
	}
	// A subscription body: base64 of a link list
	if !strings.ContainsAny(data, " \n:") || (!strings.Contains(data, "://") && len(data) > 40) {
		if b, err := b64(data); err == nil && strings.Contains(string(b), "://") {
			data = strings.TrimSpace(string(b))
		}
	}
	// Several share links / keys, one per line
	if items := splitLinks(data); len(items) > 1 {
		return parseList(items)
	}
	c, err := providers.Import(filename, data)
	if err != nil {
		return nil, err
	}
	c.ID = config.NewID("c")
	if c.Name == "" {
		c.Name = strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	}
	return &Result{Kind: "single", Connections: []config.Connection{*c}}, nil
}

var linkPrefixes = []string{"vpn://", "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://", "socks5://", "socks://"}

func isLink(line string) bool {
	low := strings.ToLower(line)
	for _, p := range linkPrefixes {
		if strings.HasPrefix(low, p) {
			return true
		}
	}
	return false
}

// splitLinks returns share links if the text is made of them (blank lines
// and #comments are allowed between).
func splitLinks(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if !isLink(line) {
			return nil
		}
		out = append(out, line)
	}
	return out
}

func parseList(items []string) (*Result, error) {
	res := &Result{Kind: "list"}
	names := map[string]int{}
	for i, it := range items {
		c, err := providers.Import("", it)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("строка %d пропущена: %v", i+1, err))
			continue
		}
		c.ID = config.NewID("c")
		c.Name = uniqueName(names, c.Name)
		res.Connections = append(res.Connections, *c)
	}
	if len(res.Connections) == 0 {
		return nil, errors.New("ни одну ссылку не удалось распознать: " + strings.Join(res.Notes, "; "))
	}
	return res, nil
}

func uniqueName(seen map[string]int, name string) string {
	if name == "" {
		name = "Подключение"
	}
	seen[name]++
	if seen[name] == 1 {
		return name
	}
	return fmt.Sprintf("%s (%d)", name, seen[name])
}

// ---- VPNer profile ----

func parseProfile(data string) (*Result, error) {
	var p Profile
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil, fmt.Errorf("файл профиля повреждён: %v", err)
	}
	if p.VPNer > ProfileVersion {
		return nil, fmt.Errorf("профиль создан более новой версией VPNer (формат %d)", p.VPNer)
	}
	res := &Result{Kind: "profile", Settings: p.Settings}
	idMap := map[string]string{}
	for _, c := range p.Connections {
		if _, err := providers.Get(c.Type); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("«%s»: тип %s не поддерживается — пропущено", c.Name, c.Type))
			continue
		}
		nid := config.NewID("c")
		idMap[c.ID] = nid
		c.ID = nid
		if c.Params == nil {
			c.Params = map[string]string{}
		}
		if c.Secrets == nil {
			c.Secrets = map[string]string{}
		}
		// Identity of VM connections (address, MACs) is per computer.
		for _, k := range []string{"lanIp", "wanMac", "lanMac"} {
			delete(c.Params, k)
		}
		delete(c.Secrets, "gwPass")
		res.Connections = append(res.Connections, c)
	}
	mapTarget := func(t string) string {
		if t == config.TargetDirect || t == config.TargetBlock {
			return t
		}
		if n, ok := idMap[t]; ok {
			return n
		}
		return config.TargetBlock
	}
	for _, r := range p.Rules {
		r.ID = config.NewID("r")
		r.Target = mapTarget(r.Target)
		res.Rules = append(res.Rules, r)
	}
	if p.Settings != nil {
		s := *p.Settings
		s.FinalTarget = mapTarget(s.FinalTarget)
		res.FinalTarget = s.FinalTarget
		res.Settings = &s
	}
	if p.DNS != nil {
		d := *p.DNS
		var servers []config.DNSServer
		dropped := map[string]bool{}
		for _, sv := range d.Servers {
			if sv.Via != "" {
				n, ok := idMap[sv.Via]
				if !ok {
					dropped[sv.ID] = true
					continue
				}
				sv.Via = n
			}
			servers = append(servers, sv)
		}
		d.Servers = servers
		var rules []config.DNSRule
		for _, r := range d.Rules {
			if !dropped[r.Server] {
				rules = append(rules, r)
			}
		}
		d.Rules = rules
		var def []string
		for _, id := range d.Default {
			if !dropped[id] {
				def = append(def, id)
			}
		}
		d.Default = def
		if len(d.Default) > 0 {
			res.DNS = &d
		}
	}
	missing := 0
	for _, c := range res.Connections {
		p, _ := providers.Get(c.Type)
		for _, f := range p.Fields() {
			if f.Secret && f.Required && c.S(f.Key) == "" {
				missing++
				break
			}
		}
	}
	if missing > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("профиль без паролей и ключей: у %d подключений их нужно будет ввести заново", missing))
	}
	return res, nil
}

// Export builds a profile; secrets are included only when asked.
func Export(cfg *config.Config, withSecrets bool) ([]byte, error) {
	p := Profile{VPNer: ProfileVersion, Rules: cfg.Rules, Settings: &cfg.Settings, DNS: &cfg.DNS}
	for _, c := range cfg.Connections {
		c.Params = copyMap(c.Params)
		c.Secrets = copyMap(c.Secrets)
		delete(c.Secrets, "gwPass")
		if !withSecrets {
			c.Secrets = nil
		}
		p.Connections = append(p.Connections, c)
	}
	return json.MarshalIndent(p, "", "  ")
}

func copyMap(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---- Clash / mihomo ----

func looksLikeClash(data string) bool {
	if !strings.Contains(data, "proxies:") {
		return false
	}
	var probe map[string]any
	if yaml.Unmarshal([]byte(data), &probe) != nil {
		return false
	}
	_, ok := probe["proxies"].([]any)
	return ok
}

type clashConfig struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

var clashKinds = map[string]string{
	"DOMAIN": config.RuleDomain, "DOMAIN-SUFFIX": config.RuleDomainSuffix, "DOMAIN-KEYWORD": config.RuleDomainKeyword,
	"DOMAIN-REGEX": config.RuleDomainRegex, "IP-CIDR": config.RuleIPCIDR, "IP-CIDR6": config.RuleIPCIDR,
	"GEOSITE": config.RuleGeoSite, "GEOIP": config.RuleGeoIP, "PROCESS-NAME": config.RuleProcess,
	"PROCESS-PATH": config.RuleProcessPath, "DST-PORT": config.RuleDstPort, "NETWORK": config.RuleNetwork,
}

func parseClash(data string) (*Result, error) {
	var cc clashConfig
	if err := yaml.Unmarshal([]byte(data), &cc); err != nil {
		return nil, fmt.Errorf("YAML: %v", err)
	}
	res := &Result{Kind: "clash"}
	byName := map[string]string{} // proxy name -> connection id
	names := map[string]int{}
	for _, p := range cc.Proxies {
		name, _ := p["name"].(string)
		typ, _ := p["type"].(string)
		if typ == "" {
			continue
		}
		body := map[string]any{}
		for k, v := range p {
			if k != "name" {
				body[k] = v
			}
		}
		y, err := yaml.Marshal(body)
		if err != nil {
			continue
		}
		c := config.Connection{ID: config.NewID("c"), Name: uniqueName(names, name), Type: "mihomo", Enabled: true,
			Params: map[string]string{}, Secrets: map[string]string{"yaml": string(y)}}
		if err := providers.Validate(&c); err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("«%s» пропущено: %v", name, err))
			continue
		}
		byName[name] = c.ID
		res.Connections = append(res.Connections, c)
	}
	if len(res.Connections) == 0 {
		return nil, errors.New("в конфиге нет поддерживаемых прокси")
	}
	// groups: resolve to their first concrete member (VPNer routes rules to
	// one connection; failover groups would hide outages from the user)
	groups := map[string][]string{}
	for _, g := range cc.Groups {
		groups[g.Name] = g.Proxies
	}
	var resolve func(string, int) string
	resolve = func(name string, depth int) string {
		switch strings.ToUpper(name) {
		case "DIRECT":
			return config.TargetDirect
		case "REJECT", "REJECT-DROP", "PASS":
			return config.TargetBlock
		}
		if id, ok := byName[name]; ok {
			return id
		}
		if members, ok := groups[name]; ok && depth < 8 {
			for _, m := range members {
				if t := resolve(m, depth+1); t != "" {
					return t
				}
			}
		}
		return ""
	}
	groupNotes := map[string]bool{}
	target := func(name string) string {
		t := resolve(name, 0)
		if _, isGroup := groups[name]; isGroup && !groupNotes[name] {
			groupNotes[name] = true
			res.Notes = append(res.Notes, fmt.Sprintf("группа «%s» → %s", name, displayTarget(t, res.Connections)))
		}
		if t == "" {
			return config.TargetBlock
		}
		return t
	}
	skipped := map[string]int{}
	for _, line := range cc.Rules {
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		kindName := strings.ToUpper(parts[0])
		if kindName == "MATCH" && len(parts) >= 2 {
			res.FinalTarget = target(parts[1])
			continue
		}
		kind, ok := clashKinds[kindName]
		if !ok || len(parts) < 3 {
			skipped[kindName]++
			continue
		}
		r := config.Rule{Enabled: true, Kind: kind, Values: []string{parts[1]}, Target: target(parts[2])}
		if kind == config.RuleIPCIDR || kind == config.RuleGeoIP {
			r.Resolve = !(len(parts) > 3 && strings.EqualFold(parts[3], "no-resolve"))
		}
		// merge consecutive rules of the same kind and target
		if n := len(res.Rules); n > 0 {
			last := &res.Rules[n-1]
			if last.Kind == r.Kind && last.Target == r.Target && last.Resolve == r.Resolve {
				last.Values = append(last.Values, r.Values...)
				continue
			}
		}
		r.ID = config.NewID("r")
		res.Rules = append(res.Rules, r)
	}
	if len(skipped) > 0 {
		var kinds []string
		for k, n := range skipped {
			kinds = append(kinds, fmt.Sprintf("%s ×%d", k, n))
		}
		sort.Strings(kinds)
		res.Notes = append(res.Notes, "не перенесены правила: "+strings.Join(kinds, ", "))
	}
	return res, nil
}

func displayTarget(t string, conns []config.Connection) string {
	switch t {
	case config.TargetDirect:
		return "напрямую"
	case config.TargetBlock, "":
		return "блокировать"
	}
	for _, c := range conns {
		if c.ID == t {
			return "«" + c.Name + "»"
		}
	}
	return t
}
