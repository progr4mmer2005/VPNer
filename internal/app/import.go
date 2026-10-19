package app

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"vpner/internal/config"
	"vpner/internal/importer"
)

// ImportOptions selects which parts of an import to apply.
type ImportOptions struct {
	Rules        bool `json:"rules"`
	ReplaceRules bool `json:"replaceRules"`
	Final        bool `json:"final"`
	Settings     bool `json:"settings"`
}

type ImportOutcome struct {
	importer.Summary
	IDs []string `json:"ids,omitempty"`
}

// ImportData previews (dry) or applies an import of any supported format.
func (a *App) ImportData(filename, data string, dry bool, opt ImportOptions) (*ImportOutcome, error) {
	res, err := importer.Parse(filename, data)
	if err != nil {
		return nil, err
	}
	out := &ImportOutcome{Summary: res.Summary()}
	if dry {
		return out, nil
	}
	for i := range res.Connections {
		if err := a.provisionAmnezia(&res.Connections[i]); err != nil {
			return nil, err
		}
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	cfg.Connections = append(cfg.Connections, res.Connections...)
	for _, c := range res.Connections {
		out.IDs = append(out.IDs, c.ID)
	}
	if opt.Rules && len(res.Rules) > 0 {
		if opt.ReplaceRules {
			cfg.Rules = res.Rules
		} else {
			cfg.Rules = append(cfg.Rules, res.Rules...)
		}
	}
	if opt.Settings && res.Settings != nil {
		s := *res.Settings
		s.UIPort = cfg.Settings.UIPort
		if !opt.Final {
			s.FinalTarget = cfg.Settings.FinalTarget
		}
		cfg.Settings = s
	}
	if opt.Settings && res.DNS != nil {
		cfg.DNS = *res.DNS
	}
	if opt.Settings && len(res.Appearance) > 0 {
		cfg.Appearance = res.Appearance
	}
	if opt.Final && res.FinalTarget != "" {
		cfg.Settings.FinalTarget = res.FinalTarget
	}
	if err := a.commit(cfg); err != nil {
		return nil, err
	}
	a.Log.Infof("app", "импорт (%s): подключений %d, правил %d", res.Kind, len(res.Connections), len(res.Rules))
	return out, nil
}

// Import keeps the simple single-item API.
func (a *App) Import(filename, data string) (string, error) {
	out, err := a.ImportData(filename, data, false, ImportOptions{})
	if err != nil {
		return "", err
	}
	if len(out.IDs) == 0 {
		return "", errors.New("ничего не импортировано")
	}
	return out.IDs[0], nil
}

// Export returns the whole configuration as a VPNer profile.
func (a *App) Export(withSecrets bool) ([]byte, error) {
	return importer.Export(a.Config(), withSecrets)
}

// FetchSubscription downloads a provider subscription (list of share links,
// base64 list or Clash YAML).
func (a *App) FetchSubscription(raw string) (string, error) {
	raw = NormalizeSubscription(raw)
	if strings.HasPrefix(strings.ToLower(raw), "happ://crypt") {
		return "", errors.New("это зашифрованная ссылка Happ (happ://crypt…) — её может открыть только сам Happ. Возьмите у провайдера обычную ссылку подписки https://…")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", errors.New("нужна ссылка вида https://…")
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "clash.meta/VPNer")
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return "", fmt.Errorf("подписка недоступна: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("подписка: HTTP %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// NormalizeSubscription unwraps app deep links (happ://add/<url>,
// v2raytun://import/<url>, clash://install-config?url=...) to the plain URL.
func NormalizeSubscription(raw string) string {
	raw = strings.TrimSpace(raw)
	low := strings.ToLower(raw)
	for _, p := range []string{"happ://add/", "v2raytun://import/", "hiddify://import/", "streisand://import/", "v2rayng://install-sub?url="} {
		if strings.HasPrefix(low, p) {
			rest := raw[len(p):]
			if u, err := url.QueryUnescape(rest); err == nil {
				rest = u
			}
			return strings.TrimSpace(rest)
		}
	}
	if strings.HasPrefix(low, "clash://install-config?") || strings.HasPrefix(low, "clashmeta://install-config?") {
		if u, err := url.Parse(raw); err == nil {
			if v := u.Query().Get("url"); v != "" {
				return v
			}
		}
	}
	return raw
}

// IsSubscriptionLink tells whether pasted text is a subscription address
// rather than a single proxy link.
func IsSubscriptionLink(s string) bool {
	s = NormalizeSubscription(s)
	if strings.ContainsAny(s, " \n") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return false
	}
	// http://user:pass@host:port is a proxy link; subscriptions have a path
	return u.User == nil && (strings.Trim(u.Path, "/") != "" || u.RawQuery != "")
}

var _ = config.TargetDirect
