package amnezia

import (
	"vpner/internal/i18n"

	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// XRay (VLESS REALITY over TCP) is the second service the AmneziaVPN app can
// install on a server, next to AmneziaWG. VPNer uses it for chains: a hop
// after a VPN program has to reach the server over TCP, because such
// programs often pass no UDP at all.
//
// Those programs also tend to redirect a connection by the site name in it:
// they read the name from the TLS hello and connect to that site, whatever
// address the connection was going to. REALITY shows the name of a decoy
// site, so through such a program its hello ends up at the real decoy site
// and never reaches the server. A name that resolves to the server itself is
// immune: redirected or not, the connection arrives at the server. So the
// server is told to answer one more name (the decoy name stays, for direct
// connections), and the chain's link uses it.

const (
	xrayContainer = "amnezia-xray"
	xrayDir       = "/opt/amnezia/xray"
	xrayConf      = xrayDir + "/server.json"
)

// ErrNoXRay: the server has no XRay installed by the AmneziaVPN app.
var ErrNoXRay = errors.New("xray is not installed on the server")

// XRayLink is what a chain needs to reach the server over XRay.
type XRayLink struct {
	Link    string // vless:// link with the server's own name
	Name    string // the name the link shows to the server
	Added   bool   // the name was added to the server now (XRay was restarted)
	HostKey string // SSH host key fingerprint
	// NewHello: the server's XRay is recent enough to answer only the
	// REALITY hello with X25519MLKEM768 (see engine/reality.go). A hint for
	// the first connection; VPNer finds the right hello by itself anyway.
	NewHello bool
}

// xrayNewHello reads "Xray 26.10.31 (...)" as printed by "xray version":
// servers from 26.9 on want the hello with X25519MLKEM768.
func xrayNewHello(version string) bool {
	f := strings.Fields(version)
	if len(f) < 2 || !strings.EqualFold(f[0], "Xray") {
		return false
	}
	parts := strings.Split(f[1], ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 26 || (major == 26 && minor >= 9)
}

// SelfName returns a site name that resolves to the server: the host itself
// when the key holds a domain name, else a name of the sslip.io service,
// which answers every "<address with dashes>.sslip.io" with that address.
func SelfName(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	if v4 := ip.To4(); v4 != nil {
		return strings.ReplaceAll(v4.String(), ".", "-") + ".sslip.io"
	}
	return strings.ReplaceAll(ip.String(), ":", "-") + ".sslip.io"
}

// xrayInbound is what VPNer reads from the server's XRay config.
type xrayInbound struct {
	Port  int
	Flow  string
	Names []string
}

// xrayAddName adds a name to the REALITY inbound of an XRay server config.
// The config comes back unchanged (changed=false) when the name is there.
func xrayAddName(conf, name string) (out string, in xrayInbound, changed bool, err error) {
	var root map[string]any
	dec := json.NewDecoder(strings.NewReader(conf))
	dec.UseNumber()
	if err = dec.Decode(&root); err != nil {
		return "", in, false, fmt.Errorf(i18n.T("amnezia.xrayConfigUnreadable"), err)
	}
	inbounds, _ := root["inbounds"].([]any)
	for _, ib := range inbounds {
		m, _ := ib.(map[string]any)
		ss, _ := m["streamSettings"].(map[string]any)
		rs, _ := ss["realitySettings"].(map[string]any)
		if m["protocol"] != "vless" || rs == nil {
			continue
		}
		if n, ok := m["port"].(json.Number); ok {
			in.Port, _ = strconv.Atoi(n.String())
		}
		if set, ok := m["settings"].(map[string]any); ok {
			if cl, _ := set["clients"].([]any); len(cl) > 0 {
				if c0, ok := cl[0].(map[string]any); ok {
					in.Flow, _ = c0["flow"].(string)
				}
			}
		}
		names, _ := rs["serverNames"].([]any)
		has := false
		for _, n := range names {
			s, _ := n.(string)
			in.Names = append(in.Names, s)
			has = has || strings.EqualFold(s, name)
		}
		if in.Port == 0 {
			return "", in, false, errors.New(i18n.T("amnezia.xrayConfigNoReality"))
		}
		if has {
			return conf, in, false, nil
		}
		rs["serverNames"] = append(names, name)
		in.Names = append(in.Names, name)
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "    ")
		if err = enc.Encode(root); err != nil {
			return "", in, false, err
		}
		return b.String(), in, true, nil
	}
	return "", in, false, errors.New(i18n.T("amnezia.xrayConfigNoReality"))
}

// xrayLink builds the vless:// link of the server's first user.
func xrayLink(host string, in xrayInbound, uuid, pub, sid, name, title string) string {
	q := url.Values{}
	q.Set("encryption", "none")
	if in.Flow != "" {
		q.Set("flow", in.Flow)
	}
	q.Set("security", "reality")
	q.Set("sni", name)
	q.Set("fp", "chrome")
	q.Set("pbk", pub)
	if sid != "" {
		q.Set("sid", sid)
	}
	q.Set("type", "tcp")
	return fmt.Sprintf("vless://%s@%s?%s#%s", uuid, net.JoinHostPort(host, strconv.Itoa(in.Port)), q.Encode(), url.PathEscape(title))
}

// xrayExec runs a command in the XRay container. The container is Alpine:
// plain sh, unlike the AmneziaWG one.
func (s *session) xrayExec(cmd string) (string, error) {
	return s.run("docker exec -i " + xrayContainer + " sh -c " + shQuote(cmd))
}

// XRayForChain makes the server's XRay answer the server's own name and
// returns a link that uses it. A server whose XRay already answers the name
// is not touched. Otherwise the config gets the name (the old one is kept
// next to it as server.json.vpner-backup), is checked by XRay itself, and
// only then XRay is restarted; AmneziaWG and other services are not touched.
func XRayForChain(k *AdminKey, title, expectHostKey string, logf func(string)) (*XRayLink, error) {
	s, err := dial(k, expectHostKey)
	if err != nil {
		return nil, err
	}
	defer s.close()
	state, err := s.run("docker inspect -f '{{.State.Running}}' " + xrayContainer + " 2>/dev/null || echo absent")
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(state) {
	case "true":
	case "false":
		return nil, errors.New(i18n.T("amnezia.xrayStopped"))
	default:
		return nil, ErrNoXRay
	}
	read := func(file string) (string, error) {
		out, err := s.xrayExec("cat " + xrayDir + "/" + file)
		return strings.TrimSpace(out), err
	}
	conf, err := read("server.json")
	if err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.couldNotReadServerConfig"), xrayConf, err)
	}
	uuid, err1 := read("xray_uuid.key")
	pub, err2 := read("xray_public.key")
	sid, _ := read("xray_short_id.key")
	if err1 != nil || err2 != nil || uuid == "" || pub == "" {
		return nil, errors.New(i18n.T("amnezia.xrayNoKeys"))
	}
	name := SelfName(k.Host)
	next, in, changed, err := xrayAddName(conf, name)
	if err != nil {
		return nil, err
	}
	version, _ := s.xrayExec("xray version")
	res := &XRayLink{Name: name, HostKey: s.host, NewHello: xrayNewHello(version),
		Link: xrayLink(k.Host, in, uuid, pub, sid, name, title)}
	if !changed {
		logf(fmt.Sprintf(i18n.T("amnezia.xrayNameAlready"), name))
		return res, nil
	}
	// The new config goes next to the old one and is checked by XRay before
	// it takes its place: a config XRay rejects would leave the server
	// without XRay after the restart.
	// (XRay tells the format of a config by its extension.)
	b64 := base64.StdEncoding.EncodeToString([]byte(next))
	tmp := xrayDir + "/server.vpner-new.json"
	check := fmt.Sprintf("echo %s | base64 -d > %[2]s && xray run -test -c %[2]s", b64, tmp)
	if out, err := s.xrayExec(check); err != nil {
		s.xrayExec("rm -f " + tmp)
		return nil, fmt.Errorf(i18n.T("amnezia.xrayConfigRejected"), err, strings.TrimSpace(out))
	}
	swap := fmt.Sprintf("cp %[1]s %[1]s.vpner-backup && mv %[2]s %[1]s", xrayConf, tmp)
	if _, err := s.xrayExec(swap); err != nil {
		return nil, err
	}
	logf(fmt.Sprintf(i18n.T("amnezia.xrayNameAdded"), name))
	if _, err := s.run("docker restart " + xrayContainer); err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.xrayRestartFailed"), err)
	}
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if out, err := s.xrayExec("pidof xray"); err == nil && strings.TrimSpace(out) != "" {
			res.Added = true
			logf(i18n.T("amnezia.xrayRestarted"))
			return res, nil
		}
	}
	// XRay did not come up with the new config: the old one goes back.
	s.xrayExec(fmt.Sprintf("cp %[1]s.vpner-backup %[1]s", xrayConf))
	s.run("docker restart " + xrayContainer)
	return nil, errors.New(i18n.T("amnezia.xrayDidNotStart"))
}
