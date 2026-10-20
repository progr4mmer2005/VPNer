// Package amnezia works with "full access" AmneziaVPN keys: it connects to
// the user's own server over SSH and adds (or removes) a dedicated client for
// VPNer exactly the way the AmneziaVPN app does it, so VPNer gets its own
// keys and never collides with the app.
package amnezia

import (
	"vpner/internal/i18n"

	"bytes"
	"compress/zlib"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// AdminKey is a decoded full-access key.
type AdminKey struct {
	Host        string
	SSHPort     int
	User        string
	Secret      string // password or private key
	Description string
	DNS1, DNS2  string
	Container   string         // e.g. amnezia-awg2
	Params      map[string]any // protocol settings from the key (port, Jc, H1...)
}

// DecodeKey unpacks a vpn:// key (qCompress JSON, base64url).
func DecodeKey(key string) (map[string]any, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), "vpn://"))
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err = enc.DecodeString(raw); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New(i18n.T("amnezia.vpnKeyInvalidBase64"))
	}
	var js []byte
	if len(b) > 4 {
		if zr, zerr := zlib.NewReader(bytes.NewReader(b[4:])); zerr == nil {
			js, _ = io.ReadAll(zr)
		}
	}
	if len(js) == 0 {
		js = b
	}
	var root map[string]any
	if err := json.Unmarshal(js, &root); err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.vpnKeyNotJson"), err)
	}
	return root, nil
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return ""
}

// IsAdminKey reports whether the key gives full (SSH) access to a server.
func IsAdminKey(key string) bool {
	root, err := DecodeKey(key)
	if err != nil {
		return false
	}
	return str(root["hostName"]) != "" && str(root["userName"]) != "" && (str(root["password"]) != "" || str(root["sshKey"]) != "")
}

// ParseAdminKey extracts SSH credentials and the AmneziaWG container.
func ParseAdminKey(key string) (*AdminKey, error) {
	root, err := DecodeKey(key)
	if err != nil {
		return nil, err
	}
	k := &AdminKey{
		Host: str(root["hostName"]), User: str(root["userName"]), Secret: str(root["password"]),
		Description: str(root["description"]), DNS1: str(root["dns1"]), DNS2: str(root["dns2"]), SSHPort: 22,
	}
	if s := str(root["sshKey"]); s != "" && k.Secret == "" {
		k.Secret = s
	}
	if p, err := strconv.Atoi(str(root["port"])); err == nil && p > 0 {
		k.SSHPort = p
	}
	if k.Host == "" || k.User == "" || k.Secret == "" {
		return nil, errors.New(i18n.T("amnezia.thisIsNotFullAccess"))
	}
	def := str(root["defaultContainer"])
	conts, _ := root["containers"].([]any)
	type cand struct {
		name   string
		params map[string]any
	}
	var cands []cand
	for _, ci := range conts {
		cm, _ := ci.(map[string]any)
		name := str(cm["container"])
		for _, proto := range []string{"awg", "wireguard"} {
			if pm, ok := cm[proto].(map[string]any); ok {
				c := cand{name, pm}
				if name == def {
					cands = append([]cand{c}, cands...)
				} else {
					cands = append(cands, c)
				}
			}
		}
		if strings.HasPrefix(name, "amnezia-awg") || name == "amnezia-wireguard" {
			if _, seen := cm["awg"]; !seen {
				if _, seen2 := cm["wireguard"]; !seen2 {
					cands = append(cands, cand{name, map[string]any{}})
				}
			}
		}
	}
	if len(cands) == 0 {
		return nil, errors.New(i18n.T("amnezia.keysServerHasNoAmneziawg"))
	}
	k.Container, k.Params = cands[0].name, cands[0].params
	return k, nil
}

// layout describes where a container keeps its server config.
type layout struct {
	conf, pub, psk, tool, iface string
}

func layoutFor(container string) layout {
	switch container {
	case "amnezia-awg2":
		return layout{"/opt/amnezia/awg/awg0.conf", "/opt/amnezia/awg/wireguard_server_public_key.key", "/opt/amnezia/awg/wireguard_psk.key", "awg", "awg0"}
	case "amnezia-wireguard":
		return layout{"/opt/amnezia/wireguard/wg0.conf", "/opt/amnezia/wireguard/wireguard_server_public_key.key", "/opt/amnezia/wireguard/wireguard_psk.key", "wg", "wg0"}
	default: // amnezia-awg (legacy)
		return layout{"/opt/amnezia/awg/wg0.conf", "/opt/amnezia/awg/wireguard_server_public_key.key", "/opt/amnezia/awg/wireguard_psk.key", "wg", "wg0"}
	}
}

// ---- SSH ----

type session struct {
	cl   *ssh.Client
	k    *AdminKey
	host string // host key fingerprint
}

func dial(k *AdminKey, expectHostKey string) (*session, error) {
	auths := []ssh.AuthMethod{}
	if strings.Contains(k.Secret, "PRIVATE KEY") {
		signer, err := ssh.ParsePrivateKey([]byte(k.Secret))
		if err != nil {
			return nil, fmt.Errorf(i18n.T("amnezia.sshKeyInAmneziaKey"), err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	} else {
		auths = append(auths, ssh.Password(k.Secret), ssh.KeyboardInteractive(
			func(_, _ string, qs []string, _ []bool) ([]string, error) {
				out := make([]string, len(qs))
				for i := range out {
					out[i] = k.Secret
				}
				return out, nil
			}))
	}
	s := &session{k: k}
	cfg := &ssh.ClientConfig{
		User: k.User, Auth: auths, Timeout: 20 * time.Second,
		// Trust on first use, like the AmneziaVPN app; later connections
		// must present the same host key.
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fp := ssh.FingerprintSHA256(key)
			if expectHostKey != "" && fp != expectHostKey {
				return fmt.Errorf(i18n.T("amnezia.serverKeyChangedExpectedPossible"), fp, expectHostKey)
			}
			s.host = fp
			return nil
		},
	}
	cl, err := ssh.Dial("tcp", net.JoinHostPort(k.Host, strconv.Itoa(k.SSHPort)), cfg)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.couldNotConnectToServer"), err)
	}
	s.cl = cl
	return s, nil
}

func (s *session) close() { s.cl.Close() }

// run executes a shell command on the server (with sudo for non-root users).
func (s *session) run(cmd string) (string, error) {
	ss, err := s.cl.NewSession()
	if err != nil {
		return "", err
	}
	defer ss.Close()
	var out, errb bytes.Buffer
	ss.Stdout, ss.Stderr = &out, &errb
	if s.k.User != "root" {
		cmd = "sudo -S -p '' sh -c " + shQuote(cmd)
		if !strings.Contains(s.k.Secret, "PRIVATE KEY") {
			ss.Stdin = strings.NewReader(s.k.Secret + "\n")
		}
	}
	if err := ss.Run(cmd); err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, strings.TrimSpace(errb.String()))
	}
	return out.String(), nil
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'" }

// inContainer runs a command inside the Amnezia container.
func (s *session) inContainer(container, cmd string) (string, error) {
	return s.run("docker exec -i " + container + " bash -c " + shQuote(cmd))
}

// ---- keys and addresses ----

func genKeyPair() (priv, pub string, err error) {
	var k [32]byte
	if _, err = rand.Read(k[:]); err != nil {
		return
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		return
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p), nil
}

var allowedIPRe = regexp.MustCompile(`AllowedIPs\s*=\s*(\d+\.\d+\.\d+\.\d+)`)

// nextIP follows the AmneziaVPN app's rule: last peer address + 1, skipping
// .255/.0; the subnet address itself when there are no peers yet.
func nextIP(serverConf, subnet string) (string, error) {
	m := allowedIPRe.FindAllStringSubmatch(serverConf, -1)
	used := map[uint32]bool{}
	var last uint32
	for _, x := range m {
		if ip := net.ParseIP(x[1]).To4(); ip != nil {
			v := binary.BigEndian.Uint32(ip)
			used[v] = true
			last = v
		}
	}
	if len(m) == 0 {
		ip := net.ParseIP(subnet).To4()
		if ip == nil {
			ip = net.ParseIP("10.8.1.0").To4()
		}
		last = binary.BigEndian.Uint32(ip) + 1 // .1 is the server itself
	}
	for i := 0; i < 1000; i++ {
		last++
		switch last & 0xff {
		case 0, 255:
			continue
		}
		if !used[last] {
			out := make(net.IP, 4)
			binary.BigEndian.PutUint32(out, last)
			return out.String(), nil
		}
	}
	return "", errors.New(i18n.T("amnezia.noFreeAddressesLeftOn"))
}

// serverParams reads obfuscation settings from the server config; the
// commented "# I1 = ..." lines hold client-side values written by the app.
func serverParams(conf string) map[string]string {
	out := map[string]string{}
	inIface := false
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.EqualFold(t, "[Interface]"):
			inIface = true
			continue
		case strings.HasPrefix(t, "["):
			inIface = false
			continue
		}
		if !inIface {
			continue
		}
		t = strings.TrimSpace(strings.TrimPrefix(t, "#"))
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if v == "" || strings.HasPrefix(v, "$") {
			continue
		}
		out[k] = v
	}
	return out
}

// client config keys copied from the server/key settings, in template order
var obfsKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
	"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime",
	"KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}

// Result of provisioning.
type Result struct {
	Config   string // client .conf for VPNer
	ClientID string // client public key on the server
	HostKey  string // SSH host key fingerprint (trust on first use)
	IP       string
}

// AddClient creates a new client on the server and returns its config.
func AddClient(k *AdminKey, clientName, expectHostKey string, logf func(string)) (*Result, error) {
	s, err := dial(k, expectHostKey)
	if err != nil {
		return nil, err
	}
	defer s.close()
	lay := layoutFor(k.Container)
	logf(fmt.Sprintf(i18n.T("amnezia.connectedToServerReadingSettings"), k.Container))
	conf, err := s.inContainer(k.Container, "cat "+lay.conf)
	if err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.couldNotReadServerConfig"), lay.conf, err)
	}
	serverPub, err := s.inContainer(k.Container, "cat "+lay.pub)
	if err != nil {
		return nil, err
	}
	psk, err := s.inContainer(k.Container, "cat "+lay.psk)
	if err != nil {
		return nil, err
	}
	serverPub, psk = strings.TrimSpace(serverPub), strings.TrimSpace(psk)
	if serverPub == "" || psk == "" {
		return nil, errors.New(i18n.T("amnezia.serverHasNoAmneziawgKeys"))
	}
	ip, err := nextIP(conf, str(k.Params["subnet_address"]))
	if err != nil {
		return nil, err
	}
	priv, pub, err := genKeyPair()
	if err != nil {
		return nil, err
	}
	// add the peer exactly like the app: append and syncconf (no restart)
	block := fmt.Sprintf("\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", pub, psk, ip)
	cmd := fmt.Sprintf("cp %[1]s %[1]s.vpner-backup && echo %[2]s | base64 -d >> %[1]s && %[3]s syncconf %[4]s <(%[3]s-quick strip %[1]s)",
		lay.conf, base64.StdEncoding.EncodeToString([]byte(block)), lay.tool, lay.iface)
	if _, err := s.inContainer(k.Container, cmd); err != nil {
		return nil, fmt.Errorf(i18n.T("amnezia.couldNotAddClientTo"), err)
	}
	logf(fmt.Sprintf(i18n.T("amnezia.clientWithAddressCreatedOn"), clientName, ip))
	addToClientsTable(s, k.Container, pub, clientName, logf)

	params := serverParams(conf)
	for _, key := range obfsKeys {
		if v := str(k.Params[key]); v != "" && params[key] == "" {
			params[key] = v
		}
	}
	dns1, dns2 := k.DNS1, k.DNS2
	if dns1 == "" {
		dns1 = "1.1.1.1"
	}
	if dns2 == "" {
		dns2 = "1.0.0.1"
	}
	port := str(k.Params["port"])
	if port == "" {
		port = params["ListenPort"]
	}
	if port == "" {
		return nil, errors.New(i18n.T("amnezia.couldNotFindAmneziawgPort"))
	}
	mtu := str(k.Params["mtu"])
	if mtu == "" {
		mtu = "1376"
	}
	keepalive := str(k.Params["persistent_keep_alive"])
	if keepalive == "" {
		keepalive = "25"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nAddress = %s/32\nDNS = %s, %s\nPrivateKey = %s\nMTU = %s\n", ip, dns1, dns2, priv, mtu)
	if pv := str(k.Params["protocol_version"]); pv != "" {
		fmt.Fprintf(&b, "ProtocolVersion = %s\n", pv)
	}
	for _, key := range obfsKeys {
		if v := params[key]; v != "" {
			fmt.Fprintf(&b, "%s = %s\n", key, v)
		}
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = %s:%s\nPersistentKeepalive = %s\n",
		serverPub, psk, k.Host, port, keepalive)
	return &Result{Config: b.String(), ClientID: pub, HostKey: s.host, IP: ip}, nil
}

func addToClientsTable(s *session, container, clientID, name string, logf func(string)) {
	path := "/opt/amnezia/" + container + "/clientsTable"
	raw, err := s.inContainer(container, "cat "+path+" 2>/dev/null || true")
	if err != nil {
		return
	}
	var table []map[string]any
	if strings.TrimSpace(raw) != "" {
		if err := json.Unmarshal([]byte(raw), &table); err != nil {
			logf(i18n.T("amnezia.serversUserListHasUnknown"))
			return
		}
	}
	table = append(table, map[string]any{"clientId": clientID, "userData": map[string]any{
		"clientName": name, "creationDate": time.Now().Format("Mon Jan 2 15:04:05 2006")}})
	b, _ := json.Marshal(table)
	cmd := fmt.Sprintf("mkdir -p /opt/amnezia/%s && echo %s | base64 -d > %s", container, base64.StdEncoding.EncodeToString(b), path)
	if _, err := s.inContainer(container, cmd); err == nil {
		logf(i18n.T("amnezia.clientAddedToUserList"))
	}
}

// RemoveClient deletes VPNer's client from the server (when the connection
// is deleted in VPNer).
func RemoveClient(k *AdminKey, clientID, expectHostKey string) error {
	s, err := dial(k, expectHostKey)
	if err != nil {
		return err
	}
	defer s.close()
	lay := layoutFor(k.Container)
	conf, err := s.inContainer(k.Container, "cat "+lay.conf)
	if err != nil {
		return err
	}
	kept := removePeer(conf, clientID)
	if kept == conf {
		return nil
	}
	cmd := fmt.Sprintf("cp %[1]s %[1]s.vpner-backup && echo %[2]s | base64 -d > %[1]s && %[3]s syncconf %[4]s <(%[3]s-quick strip %[1]s)",
		lay.conf, base64.StdEncoding.EncodeToString([]byte(kept)), lay.tool, lay.iface)
	if _, err := s.inContainer(k.Container, cmd); err != nil {
		return err
	}
	path := "/opt/amnezia/" + k.Container + "/clientsTable"
	if raw, err := s.inContainer(k.Container, "cat "+path+" 2>/dev/null || true"); err == nil {
		var table []map[string]any
		if json.Unmarshal([]byte(raw), &table) == nil {
			var out []map[string]any
			for _, row := range table {
				if str(row["clientId"]) != clientID {
					out = append(out, row)
				}
			}
			b, _ := json.Marshal(out)
			s.inContainer(k.Container, fmt.Sprintf("echo %s | base64 -d > %s", base64.StdEncoding.EncodeToString(b), path))
		}
	}
	return nil
}

// removePeer drops the [Peer] section with the given public key.
func removePeer(conf, pub string) string {
	sections := strings.Split(conf, "[Peer]")
	out := []string{sections[0]}
	for _, sec := range sections[1:] {
		if strings.Contains(sec, pub) {
			continue
		}
		out = append(out, sec)
	}
	res := strings.Join(out, "[Peer]")
	return strings.TrimRight(res, "\n") + "\n"
}

// Fingerprint of the server for display.
func Fingerprint(k *AdminKey) string {
	h := sha256.Sum256([]byte(k.Host + ":" + strconv.Itoa(k.SSHPort)))
	return base64.RawStdEncoding.EncodeToString(h[:6])
}

var _ = sort.Strings
