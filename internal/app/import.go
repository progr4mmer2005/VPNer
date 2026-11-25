package app

import (
	"vpner/internal/i18n"

	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vpner/internal/config"
	"vpner/internal/importer"
	"vpner/internal/providers"
)

// Params VPNer puts on connections that came from a subscription: which
// subscription (a hash of its link, never the link) and its title, so the
// chain editor can tell two servers of one provider.
const (
	ParamSub     = "sub"
	ParamSubName = "subName"
)

// ImportOptions selects which parts of an import to apply.
type ImportOptions struct {
	// Source / SourceName mark the imported connections as servers of one
	// subscription (ParamSub, ParamSubName). Set by the server, not the UI.
	Source       string `json:"-"`
	SourceName   string `json:"-"`
	Rules        bool   `json:"rules"`
	ReplaceRules bool   `json:"replaceRules"`
	Final        bool   `json:"final"`
	Settings     bool   `json:"settings"`
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
		if c := &res.Connections[i]; opt.Source != "" {
			if c.Params == nil {
				c.Params = map[string]string{}
			}
			c.Params[ParamSub], c.Params[ParamSubName] = opt.Source, opt.SourceName
		}
	}
	a.ops.Lock()
	defer a.ops.Unlock()
	cfg := a.Config()
	cfg.Connections = append(cfg.Connections, res.Connections...)
	// Chains whose own server users did not come with the profile (it was
	// exported without secrets) get new ones.
	for i := range cfg.Connections {
		if c := &cfg.Connections[i]; c.Type == config.TypeChain && isNew(res.Connections, c.ID) {
			if err := a.provisionChainKeys(c, cfg); err != nil {
				return nil, err
			}
		}
	}
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
	a.Log.Infof("app", i18n.T("app.importConnectionsRules"), res.Kind, len(res.Connections), len(res.Rules))
	return out, nil
}

// Import keeps the simple single-item API.
func (a *App) Import(filename, data string) (string, error) {
	out, err := a.ImportData(filename, data, false, ImportOptions{})
	if err != nil {
		return "", err
	}
	if len(out.IDs) == 0 {
		return "", errors.New(i18n.T("app.nothingWasImported"))
	}
	return out.IDs[0], nil
}

// Export returns the whole configuration as a VPNer profile.
func (a *App) Export(withSecrets bool) ([]byte, error) {
	return importer.Export(a.Config(), withSecrets)
}

// FetchSubscription downloads a provider subscription (list of share links,
// base64 list or Clash YAML).
// How VPNer introduces itself when it downloads a subscription. Some VPN
// services give their servers only to their own app, and count devices by
// a device code the app sends (x-hwid): every server of the subscription
// is the same device.
const (
	SubAsClient = ""     // a Clash client, no device code
	SubAsIncy   = "incy" // the INCY app of this computer, with its device code
	SubAsOwn    = "own"  // the INCY app with a device code of VPNer's own
)

// incyHWID is the device code the INCY app on this computer sends: it keeps
// it in %APPDATA%\incy\hwid.
func incyHWID() string {
	b, err := os.ReadFile(filepath.Join(os.Getenv("APPDATA"), "incy", "hwid"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ownHWID is VPNer's own device code, made once and kept in the data folder.
func (a *App) ownHWID() (string, error) {
	p := filepath.Join(a.DataDir, "device-hwid")
	if b, err := os.ReadFile(p); err == nil && len(strings.TrimSpace(string(b))) > 0 {
		return strings.TrimSpace(string(b)), nil
	}
	id := strings.ToUpper(randUUID())
	return id, os.WriteFile(p, []byte(id), 0o600)
}

// FetchSubscription downloads a provider subscription (list of share links,
// base64 list, Clash YAML or a list of XRay configs).
func (a *App) FetchSubscription(raw, as string) (body string, src Subscription, err error) {
	raw = NormalizeSubscription(raw)
	if strings.HasPrefix(strings.ToLower(raw), "happ://crypt") {
		return "", src, errors.New(i18n.T("app.thisIsEncryptedHappLink"))
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", src, errors.New(i18n.T("app.httpsLinkIsNeeded"))
	}
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "clash.meta/VPNer")
	if as == SubAsIncy || as == SubAsOwn {
		hwid := incyHWID()
		if as == SubAsOwn {
			if hwid, err = a.ownHWID(); err != nil {
				return "", src, err
			}
		} else if hwid == "" {
			return "", src, errors.New(i18n.T("app.subIncyNotFound"))
		}
		// what the INCY desktop app sends (its SubscriptionService)
		req.Header.Set("User-Agent", "INCY/1.0 (Desktop)")
		req.Header.Set("x-client", "INCY")
		req.Header.Set("x-hwid", hwid)
		req.Header.Set("x-device-os", "Windows 11")
		req.Header.Set("x-ver-os", "10.0")
		req.Header.Set("x-device-model", "amd64")
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return "", src, fmt.Errorf(i18n.T("app.subscriptionIsUnavailable"), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", src, fmt.Errorf(i18n.T("app.subscriptionHttp"), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", src, err
	}
	sum := sha256.Sum256([]byte(u.String()))
	src = Subscription{ID: hex.EncodeToString(sum[:6]), Title: subTitle(resp.Header.Get("Profile-Title"), u.Host)}
	return string(b), src, nil
}

// Subscription names where servers came from.
type Subscription struct {
	ID    string // a hash of the link
	Title string // the service's own title of it, or its host
}

// subTitle reads the Profile-Title header ("base64:..." or plain text).
func subTitle(h, host string) string {
	h = strings.TrimSpace(h)
	if v, ok := strings.CutPrefix(h, "base64:"); ok {
		if b, err := base64.StdEncoding.DecodeString(v); err == nil {
			h = strings.TrimSpace(string(b))
		}
	}
	if h == "" {
		return host
	}
	return h
}

// SubscriptionStub: instead of its servers the service gave a placeholder
// (a server on port 1 whose name says the program is not supported), as
// services do for apps they do not serve.
func SubscriptionStub(filename, data string) bool {
	res, err := importer.Parse(filename, data)
	if err != nil || len(res.Connections) == 0 || len(res.Connections) > 2 {
		return false
	}
	for i := range res.Connections {
		c := &res.Connections[i]
		p, err := providers.Get(c.Type)
		np, ok := p.(providers.NativeProvider)
		if err != nil || !ok {
			return false
		}
		m, err := np.Outbound(c)
		if err != nil || fmt.Sprint(m["port"]) != "1" {
			return false
		}
	}
	return true
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

func isNew(conns []config.Connection, id string) bool {
	for _, c := range conns {
		if c.ID == id {
			return true
		}
	}
	return false
}

var _ = config.TargetDirect

// randUUID is a random UUID (version 4), as text.
func randUUID() string {
	b, _ := hex.DecodeString(randHex(16))
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
