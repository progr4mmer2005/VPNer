package app

import (
	"vpner/internal/i18n"

	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"vpner/internal/config"
	"vpner/internal/engine"
)

// routeQuery is what the rules see of a connection.
type routeQuery struct {
	host        string // site name (from DNS or sniffed), "" for a bare IP
	ip          net.IP // destination address, nil when only the name is known
	process     string // program file name, lower case
	processPath string // full program path, lower case; "" when unknown
	port        int    // destination port, 0 when unknown
	network     string // "tcp" or "udp", "" when unknown
	// matchedRule/matchedPayload: the engine rule the connection matched when
	// it was opened ("GeoSite", "youtube"). They settle rules that only the
	// engine can evaluate (site categories, IP countries).
	matchedRule, matchedPayload string
}

type routeHit struct {
	target string // VPNer target: connection id, direct or block
	rule   string // the rule, for people
	notes  []string
	known  bool // false: a rule only the engine can evaluate came first
}

// route evaluates cfg for q in the order the engine checks rules (see
// engine.Generate). A rule that cannot be decided from q (a site category,
// an IP rule that needs the name resolved, a port rule without a port) ends
// the evaluation with known=false when strict is set; otherwise it is
// skipped, as the route check in the interface does, with a note for the
// rules people expect to be checked.
func route(cfg *config.Config, q routeQuery, strict bool) routeHit {
	var notes []string
	unknown := func(note string) bool {
		if strict {
			return true
		}
		if note != "" {
			notes = append(notes, note)
		}
		return false
	}
	s := cfg.Settings
	if s.BlockQUIC {
		if q.network == "" || q.port == 0 {
			if unknown("") {
				return routeHit{}
			}
		} else if q.network == "udp" && q.port == 443 {
			return routeHit{target: config.TargetBlock, rule: "QUIC", known: true}
		}
	}
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		for _, raw := range r.Values {
			v := strings.TrimSpace(raw)
			if v == "" || strings.HasPrefix(v, "#") {
				continue
			}
			hit, sure := ruleMatches(r, v, q)
			if !sure {
				note := ""
				if r.Kind == config.RuleGeoSite || r.Kind == config.RuleGeoIP {
					note = fmt.Sprintf(i18n.T("app.ruleIsCheckedByEngine"), r.Kind, strings.ToLower(v))
				}
				if unknown(note) {
					return routeHit{}
				}
				continue
			}
			if hit {
				return routeHit{target: r.Target, rule: fmt.Sprintf("%s: %s", kindTitle(r.Kind), raw), notes: notes, known: true}
			}
		}
	}
	// Loopback never reaches the engine; for the route check it is local too.
	if s.AllowLAN && q.ip != nil && (engine.IsLAN(q.ip) || q.ip.IsLoopback()) {
		return routeHit{target: config.TargetDirect, rule: i18n.T("app.localNetwork"), notes: notes, known: true}
	}
	return routeHit{target: s.FinalTarget, rule: i18n.T("app.defaultRule"), notes: notes, known: true}
}

// ruleMatches checks one rule value the way the engine line generated for it
// matches. sure is false when q does not hold what the decision needs.
func ruleMatches(r config.Rule, v string, q routeQuery) (hit, sure bool) {
	switch r.Kind {
	case config.RuleProcess:
		return q.process != "" && globMatch(strings.ToLower(strings.Trim(v, `"`)), q.process), true
	case config.RuleProcessPath:
		p := strings.ToLower(strings.ReplaceAll(strings.Trim(v, `"`), "/", `\`))
		if q.processPath != "" {
			return globMatch(p, q.processPath), true
		}
		// The route check knows only the program name.
		return q.process != "" && strings.Contains(p, `\`) && (globMatch(p, q.process) || strings.HasSuffix(p, `\`+q.process)), true
	case config.RuleDomain, config.RuleDomainSuffix:
		d := engine.NormalizeDomain(v)
		if q.host == "" || d == "" {
			return false, true
		}
		if r.Kind == config.RuleDomainSuffix || strings.HasPrefix(v, "*.") || strings.HasPrefix(v, ".") {
			return q.host == d || strings.HasSuffix(q.host, "."+d), true
		}
		return q.host == d, true
	case config.RuleDomainKeyword:
		return q.host != "" && strings.Contains(q.host, strings.ToLower(v)), true
	case config.RuleDomainRegex:
		re, err := regexp.Compile(v)
		return err == nil && q.host != "" && re.MatchString(q.host), true
	case config.RuleIPCIDR:
		n := parseCIDR(v)
		if n == nil {
			return false, true
		}
		if q.ip != nil {
			return n.Contains(q.ip), true
		}
		// Without an address the engine resolves the name only when asked to.
		return false, q.host == "" || !r.Resolve
	case config.RuleGeoSite:
		if q.host == "" {
			return false, true
		}
		return true, q.matched("GeoSite", v)
	case config.RuleGeoIP:
		if q.ip == nil && (q.host == "" || !r.Resolve) {
			return false, true
		}
		return true, q.matched("GeoIP", v)
	case config.RuleDstPort:
		if q.port == 0 {
			return false, false
		}
		return portMatches(v, q.port)
	case config.RuleNetwork:
		if q.network == "" {
			return false, false
		}
		return strings.EqualFold(v, q.network), true
	}
	return false, false
}

// matched reports whether the connection was opened by exactly this engine
// rule, which then certainly matches it.
func (q routeQuery) matched(rule, payload string) bool {
	return strings.EqualFold(q.matchedRule, rule) && strings.EqualFold(q.matchedPayload, payload)
}

func parseCIDR(v string) *net.IPNet {
	if !strings.Contains(v, "/") {
		ip := net.ParseIP(v)
		if ip == nil {
			return nil
		}
		if ip.To4() != nil {
			v += "/32"
		} else {
			v += "/128"
		}
	}
	_, n, err := net.ParseCIDR(v)
	if err != nil {
		return nil
	}
	return n
}

// portMatches handles "443", "6881-6889" and lists of them ("80/443").
func portMatches(v string, port int) (hit, sure bool) {
	for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == '/' || r == ',' }) {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(part), "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return false, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return false, false
			}
		}
		if port >= a && port <= b {
			return true, true
		}
	}
	return false, true
}

func globMatch(pattern, s string) bool {
	re := "^" + strings.ReplaceAll(strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, ".*"), `\?`, ".") + "$"
	ok, _ := regexp.MatchString(re, s)
	return ok
}
