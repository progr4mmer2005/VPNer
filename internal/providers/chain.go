package providers

import (
	"vpner/internal/i18n"

	"errors"
	"fmt"

	"vpner/internal/config"
)

// chainProvider is a connection made of other connections (see
// config.TypeChain). It has no outbound of its own: the engine builds it
// from the hops (engine.Chains).
type chainProvider struct{}

func init() { Register(chainProvider{}) }

func (chainProvider) Type() string        { return config.TypeChain }
func (chainProvider) Title() string       { return i18n.T("providers.chain") }
func (chainProvider) Description() string { return i18n.T("providers.chainDescription") }
func (chainProvider) Runtime() Runtime    { return RuntimeNative }

// Fields: the hops are edited by the chain editor of the UI, not by a
// generic form field.
func (chainProvider) Fields() []Field { return []Field{} }

// ServerHosts of a chain are those of its hops, which the router already
// knows; a chain has none of its own.
func (chainProvider) ServerHosts(*config.Connection) []string { return nil }

// CanFollow reports whether a connection can be a hop after the first one:
// such a hop gets its own copy that reaches the server through the
// previous hop, so it has to be a built-in protocol. The first hop can be
// any connection that is not a chain.
func CanFollow(c *config.Connection) bool { return TypeCanFollow(c.Type) }

// TypeCanFollow is CanFollow for a connection type.
func TypeCanFollow(t string) bool {
	if t == config.TypeChain || t == "interface" {
		return false
	}
	p, err := Get(t)
	if err != nil {
		return false
	}
	_, ok := p.(NativeProvider)
	return ok
}

// ValidateChains checks what config.Validate cannot: the kind of each hop.
func ValidateChains(cfg *config.Config) error {
	for _, cn := range cfg.Connections {
		if cn.Type != config.TypeChain {
			continue
		}
		for i, h := range cn.Hops() {
			hc := cfg.Conn(h)
			if hc == nil || i == 0 {
				continue
			}
			if !CanFollow(hc) {
				return fmt.Errorf(i18n.T("providers.chainHopCannotFollow"), cn.Name, hc.Name)
			}
		}
	}
	return nil
}

// A hop after the first that is an Amnezia "full access" connection gets its
// own user on the server for the chain: the chain runs a copy of the hop,
// and one WireGuard key cannot work in two places at once. The user's config
// and id are secrets of the chain, keyed by the hop's connection id.

// OwnKey reports whether a hop after the first gets its own user.
func OwnKey(hop *config.Connection) bool { return hop.Type == "amnezia-server" }

// ChainKeySecret and ChainClientSecret name the chain secrets of a hop.
func ChainKeySecret(hopID string) string    { return "hopConfig." + hopID }
func ChainClientSecret(hopID string) string { return "hopClient." + hopID }

// HopOutbound builds the outbound of a hop after the first, with the chain's
// own user when the hop has one. Without it the hop is not built: sharing
// the key with the connection itself would break both.
func HopOutbound(chain, hop *config.Connection) (map[string]any, error) {
	p, err := Get(hop.Type)
	if err != nil {
		return nil, err
	}
	np, ok := p.(NativeProvider)
	if !ok {
		return nil, fmt.Errorf(i18n.T("providers.chainHopCannotFollow"), chain.Name, hop.Name)
	}
	if !OwnKey(hop) {
		return np.Outbound(hop)
	}
	conf := chain.S(ChainKeySecret(hop.ID))
	if conf == "" {
		return nil, errors.New(i18n.T("providers.chainKeyMissing"))
	}
	tmp := *hop
	tmp.Secrets = map[string]string{}
	for k, v := range hop.Secrets {
		tmp.Secrets[k] = v
	}
	tmp.Secrets["config"] = conf
	return np.Outbound(&tmp)
}
