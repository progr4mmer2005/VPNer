package providers

import (
	"encoding/json"
	"errors"
	"strings"

	"vpner/internal/config"
	"vpner/internal/i18n"
)

// A provider subscription kept as one connection: the servers of the
// subscription live inside it, and it runs through the one the user chose.
// Any server can also be taken out as a connection of its own (a link
// connection marked with ParamSubOf / ParamSubKey) and put back.

const (
	TypeSubscription = "subscription"
	// Secrets: the subscription link and its servers (JSON, SubServer list).
	SecretSubURL     = "url"
	SecretSubServers = "servers"
	// Params of the subscription connection.
	ParamSubAs     = "as"     // how to introduce itself: "", incy, own (app.SubAs*)
	ParamSubServer = "server" // key of the chosen server
	ParamSubTitle  = "title"  // the service's title of the subscription
	// Params of a server taken out of a subscription.
	ParamSubOf  = "subOf"  // the subscription connection
	ParamSubKey = "subKey" // the server's key in it
)

// SubServer is one server of a subscription.
type SubServer struct {
	Key  string `json:"key"`  // stable within the subscription: its name
	Name string `json:"name"` // as the service names it
	Link string `json:"link"` // share link
}

// SubServers lists the servers kept in a subscription connection.
func SubServers(c *config.Connection) []SubServer {
	var out []SubServer
	json.Unmarshal([]byte(c.S(SecretSubServers)), &out)
	return out
}

// SetSubServers stores the servers of a subscription connection.
func SetSubServers(c *config.Connection, list []SubServer) {
	b, _ := json.Marshal(list)
	if c.Secrets == nil {
		c.Secrets = map[string]string{}
	}
	c.Secrets[SecretSubServers] = string(b)
}

// SubSelected is the server a subscription runs through: the chosen one,
// or the first when nothing (or a server that is gone) is chosen.
func SubSelected(c *config.Connection) (SubServer, bool) {
	list := SubServers(c)
	if len(list) == 0 {
		return SubServer{}, false
	}
	for _, s := range list {
		if s.Key == c.P(ParamSubServer) {
			return s, true
		}
	}
	return list[0], true
}

// SubKeys gives servers keys from their names; a repeated name gets " #2"...
func SubKeys(list []SubServer) []SubServer {
	seen := map[string]int{}
	for i := range list {
		k := strings.TrimSpace(list[i].Name)
		if k == "" {
			k = "server"
		}
		seen[k]++
		if n := seen[k]; n > 1 {
			k = k + " #" + itoa(n)
		}
		list[i].Key = k
	}
	return list
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

type subscriptionProvider struct{}

func init() { Register(subscriptionProvider{}) }

func (subscriptionProvider) Type() string     { return TypeSubscription }
func (subscriptionProvider) Title() string    { return i18n.T("providers.subscription") }
func (subscriptionProvider) Runtime() Runtime { return RuntimeNative }
func (subscriptionProvider) Description() string {
	return i18n.T("providers.subscriptionDesc")
}

func (subscriptionProvider) Fields() []Field {
	return []Field{
		{Key: SecretSubURL, Label: i18n.T("providers.subscriptionUrl"), Kind: "text", Secret: true, Required: true, Placeholder: "https://…"},
		{Key: ParamSubAs, Label: i18n.T("providers.subscriptionAs"), Kind: "select", Help: i18n.T("providers.subscriptionAsHelp"),
			Options: []Option{
				{Value: "", Label: i18n.T("providers.subscriptionAsClient")},
				{Value: "incy", Label: i18n.T("providers.subscriptionAsIncy")},
				{Value: "own", Label: i18n.T("providers.subscriptionAsOwn")},
			}},
	}
}

func (subscriptionProvider) Outbound(c *config.Connection) (map[string]any, error) {
	s, ok := SubSelected(c)
	if !ok {
		return nil, errors.New(i18n.T("providers.subscriptionEmpty"))
	}
	m, _, err := parseLink(strings.TrimSpace(s.Link))
	return m, err
}

func (subscriptionProvider) ServerHosts(c *config.Connection) []string {
	s, ok := SubSelected(c)
	if !ok {
		return nil
	}
	return linkProvider{}.ServerHosts(&config.Connection{Secrets: map[string]string{"link": s.Link}})
}

// LinkProto says in a few words how a share link connects: "vless · reality
// · tcp", "trojan · tls · ws"...
func LinkProto(link string) string {
	m, _, err := parseLink(strings.TrimSpace(link))
	if err != nil {
		return ""
	}
	parts := []string{fmtAny(m["type"])}
	switch {
	case m["reality-opts"] != nil:
		parts = append(parts, "reality")
	case m["tls"] == true:
		parts = append(parts, "tls")
	}
	if n := fmtAny(m["network"]); n != "" {
		parts = append(parts, n)
	}
	return strings.Join(parts, " · ")
}

func fmtAny(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
