package providers

import (
	"vpner/internal/i18n"

	"errors"
	"strings"

	"vpner/internal/amnezia"
	"vpner/internal/config"
)

// A connection created from a "full access" AmneziaVPN key: VPNer logs in to
// the user's server over SSH, creates its own client there (like the
// AmneziaVPN app does) and then works as a built-in AmneziaWG connection.
type amneziaServerProvider struct{}

func init() { Register(amneziaServerProvider{}) }

func (amneziaServerProvider) Type() string     { return "amnezia-server" }
func (amneziaServerProvider) Title() string    { return i18n.T("providers.amneziaFullAccessKey") }
func (amneziaServerProvider) Runtime() Runtime { return RuntimeNative }
func (amneziaServerProvider) Description() string {
	return i18n.T("providers.fullAccessKeyToYour")
}

func (amneziaServerProvider) Fields() []Field {
	return []Field{
		{Key: "key", Label: i18n.T("providers.fullAccessKeyVpn"), Kind: "textarea", Secret: true, Required: true,
			Help: i18n.T("providers.sameKeyThatAddsServer")},
		{Key: "clientName", Label: i18n.T("providers.userNameOnServer"), Kind: "text", Default: "VPNer"},
		{Key: "mtu", Label: i18n.T("providers.mtuEmptyFromServerSettings"), Kind: "number", Advanced: true},
	}
}

func (p amneziaServerProvider) client(c *config.Connection) (*config.Connection, error) {
	if strings.TrimSpace(c.S("config")) == "" {
		return nil, errors.New(i18n.T("providers.userOnServerIsNot"))
	}
	tmp := *c
	tmp.Secrets = map[string]string{"config": c.S("config")}
	tmp.Params = map[string]string{"mtu": c.P("mtu")}
	return &tmp, nil
}

func (p amneziaServerProvider) Outbound(c *config.Connection) (map[string]any, error) {
	if _, err := amnezia.ParseAdminKey(c.S("key")); err != nil {
		return nil, err
	}
	tmp, err := p.client(c)
	if err != nil {
		return nil, err
	}
	return wireguardProvider{}.Outbound(tmp)
}

func (p amneziaServerProvider) ServerHosts(c *config.Connection) []string {
	tmp, err := p.client(c)
	if err != nil {
		if k, err := amnezia.ParseAdminKey(c.S("key")); err == nil {
			return []string{k.Host}
		}
		return nil
	}
	return wireguardProvider{}.ServerHosts(tmp)
}

func (amneziaServerProvider) Detect(_ string, data string) bool {
	return strings.HasPrefix(strings.TrimSpace(data), "vpn://") && amnezia.IsAdminKey(data)
}

func (amneziaServerProvider) Import(_ string, data string) (*config.Connection, error) {
	k, err := amnezia.ParseAdminKey(data)
	if err != nil {
		return nil, err
	}
	name := k.Description
	if name == "" {
		name = "Amnezia " + k.Host
	}
	return &config.Connection{Name: name, Secrets: map[string]string{"key": strings.TrimSpace(data)},
		Params: map[string]string{"clientName": "VPNer"}}, nil
}
