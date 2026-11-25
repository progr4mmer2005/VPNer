package providers

import (
	"vpner/internal/i18n"

	"bufio"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"vpner/internal/bridge"
	"vpner/internal/config"
)

// ---- OpenConnect: Cisco AnyConnect / Secure Client, GlobalProtect, Fortinet, Pulse/Ivanti, F5, Array ----

type openconnectProvider struct{}

func init() { Register(openconnectProvider{}) }

func (openconnectProvider) Type() string     { return "openconnect" }
func (openconnectProvider) Title() string    { return "Cisco AnyConnect / OpenConnect" }
func (openconnectProvider) Runtime() Runtime { return RuntimeWSL }
func (openconnectProvider) Packages() []string {
	return []string{"openconnect"}
}
func (openconnectProvider) Description() string {
	return i18n.T("providers.compatibleServersCiscoAnyconnectSecure")
}

var ocProtocols = []Option{
	{"anyconnect", "Cisco AnyConnect / Secure Client"},
	{"gp", "Palo Alto GlobalProtect"},
	{"fortinet", "Fortinet SSL VPN"},
	{"pulse", "Pulse Secure / Ivanti"},
	{"nc", "Juniper Network Connect"},
	{"f5", "F5 BIG-IP"},
	{"array", "Array Networks"},
}

func (openconnectProvider) Fields() []Field {
	return []Field{
		{Key: "protocol", Label: i18n.T("providers.serverType"), Kind: "select", Default: "anyconnect", Options: ocProtocols},
		{Key: "server", Label: i18n.T("providers.server"), Kind: "text", Required: true, Placeholder: i18n.T("providers.vpnCompanyComOrVpn")},
		{Key: "username", Label: i18n.T("providers.login"), Kind: "text"},
		{Key: "password", Label: i18n.T("providers.password"), Kind: "text", Secret: true, Help: i18n.T("providers.canStayEmptyProgramAsks")},
		{Key: "mfaAnswer", Label: i18n.T("providers.answerToSecondPromptMfa"), Kind: "text", Placeholder: "push",
			Help: i18n.T("providers.ifAfterPasswordServerAsks")},
		{Key: "authgroup", Label: i18n.T("providers.groupAuthgroup"), Kind: "text", Advanced: true},
		{Key: "sso", Label: i18n.T("providers.browserSignInSamlSso"), Kind: "bool", Help: i18n.T("providers.yourOrganizationsSignInPage")},
		{Key: "servercert", Label: i18n.T("providers.serverCertificateFingerprint"), Kind: "text", Advanced: true, Placeholder: "pin-sha256:...",
			Help: i18n.T("providers.forServersWithSelfSigned")},
		{Key: "certificate", Label: i18n.T("providers.clientCertificatePemWithKey"), Kind: "textarea", Secret: true, Advanced: true},
		{Key: "useragent", Label: "User-Agent", Kind: "text", Advanced: true, Placeholder: "AnyConnect Windows 5.1.2.42"},
		fieldRouteAll(),
		fieldFallbackDNS(),
		fieldReconnect(),
		{Key: "keepAlive", Label: i18n.T("providers.keepServerFromEndingIdle"), Kind: "bool", Default: "true", Advanced: true,
			Help: i18n.T("providers.onceMinuteTinyDnsQuery")},
		{Key: "extraArgs", Label: i18n.T("providers.extraOpenconnectOptions"), Kind: "text", Advanced: true, Placeholder: "--os=win --version-string=..."},
	}
}

var unsafeArgRe = regexp.MustCompile(`^--(script|proxy|external-browser|setuid|pid-file|background|script-tun|interface)\b`)

func extraArgs(s string) ([]string, error) {
	var out []string
	for _, a := range shellSplit(s) {
		if unsafeArgRe.MatchString(a) {
			return nil, fmt.Errorf(i18n.T("providers.optionIsManagedByProgram"), a)
		}
		out = append(out, a)
	}
	return out, nil
}

func (openconnectProvider) Spec(c *config.Connection) (*bridge.ProcSpec, error) {
	server := c.P("server")
	if server == "" {
		return nil, errors.New(i18n.T("providers.noServerGiven"))
	}
	proto := c.P("protocol")
	if proto == "" {
		proto = "anyconnect"
	}
	files := map[string]bridge.File{
		"vpnc.sh": {Content: "#!/bin/sh\nexec {{agent}} hook vpnc {{id}}\n", Mode: 0o700},
	}
	argv := []string{"openconnect",
		"--protocol=" + proto,
		"--proxy=socks5://{{socks}}",
		"--no-dtls", // UDP cannot go through the SOCKS uplink; TLS transport is used
		"--script={{dir}}/vpnc.sh",
		"--reconnect-timeout=60",
	}
	if u := c.P("username"); u != "" {
		argv = append(argv, "--user="+u)
	}
	if g := c.P("authgroup"); g != "" {
		argv = append(argv, "--authgroup="+g)
	}
	if pin := c.P("servercert"); pin != "" {
		argv = append(argv, "--servercert="+pin)
	}
	if ua := c.P("useragent"); ua != "" {
		argv = append(argv, "--useragent="+ua)
	}
	if cert := c.S("certificate"); strings.TrimSpace(cert) != "" {
		files["client.pem"] = bridge.File{Content: cert}
		argv = append(argv, "--certificate={{dir}}/client.pem")
	}
	if c.Bool("sso") {
		files["sso.sh"] = bridge.File{Content: "#!/bin/sh\nexec {{agent}} hook openurl {{id}} \"$1\"\n", Mode: 0o700}
		argv = append(argv, "--external-browser={{dir}}/sso.sh")
	}
	ex, err := extraArgs(c.P("extraArgs"))
	if err != nil {
		return nil, err
	}
	argv = append(argv, ex...)
	argv = append(argv, server)

	var answers []bridge.Answer
	if m := c.P("mfaAnswer"); m != "" {
		answers = append(answers, bridge.Answer{Pattern: `(?i)second|secondary|passcode|duo|2fa|mfa|factor|otp|token|response|второй|код`, Value: m, Once: true})
	}
	if pw := c.S("password"); pw != "" {
		answers = append(answers, bridge.Answer{Pattern: `(?i)^password:?$|пароль`, Value: pw, Once: true, Retry: true})
	}
	keepAlive := 0
	if boolDefault(c, "keepAlive", true) {
		keepAlive = 60
	}
	return &bridge.ProcSpec{
		ReachedPattern: `Got HTTP response|Connected to HTTPS|SSL negotiation with`,
		ID:             c.ID, Name: c.Name, Argv: argv, Files: files, Answers: answers,
		RouteAll:    boolDefault(c, "routeAll", true),
		FallbackDNS: dnsList(c),
		Reconnect:   boolDefault(c, "reconnect", true),
		KeepAlive:   keepAlive,
	}, nil
}

func (openconnectProvider) ServerHosts(c *config.Connection) []string {
	s := c.P("server")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return []string{s}
}

func dnsList(c *config.Connection) []string {
	v := c.P("fallbackDns")
	if v == "" {
		v = "1.1.1.1 8.8.8.8"
	}
	return splitList(v)
}

// ---- OpenVPN ----

type openvpnProvider struct{}

func init() { Register(openvpnProvider{}) }

func (openvpnProvider) Type() string       { return "openvpn" }
func (openvpnProvider) Title() string      { return "OpenVPN" }
func (openvpnProvider) Runtime() Runtime   { return RuntimeWSL }
func (openvpnProvider) Packages() []string { return []string{"openvpn"} }
func (openvpnProvider) Description() string {
	return i18n.T("providers.ovpnConfigWithCertificatesInside")
}

func (openvpnProvider) Fields() []Field {
	return []Field{
		{Key: "config", Label: i18n.T("providers.ovpnConfig"), Kind: "textarea", Secret: true, Required: true, Placeholder: "client\ndev tun\nproto udp\nremote vpn.example.com 1194\n<ca>\n...\n</ca>"},
		{Key: "username", Label: i18n.T("providers.loginIfNeeded"), Kind: "text"},
		{Key: "password", Label: i18n.T("providers.password"), Kind: "text", Secret: true},
		{Key: "mfaAnswer", Label: i18n.T("providers.answerToCodePromptMfa"), Kind: "text", Placeholder: "push",
			Help: i18n.T("providers.forServersThatAskFor")},
		{Key: "keyPassword", Label: i18n.T("providers.privateKeyPassword"), Kind: "text", Secret: true, Advanced: true},
		fieldRouteAll(),
		fieldFallbackDNS(),
		fieldReconnect(),
		{Key: "extraArgs", Label: i18n.T("providers.extraOpenvpnOptions"), Kind: "text", Advanced: true},
	}
}

// Directives that are Windows-only, conflict with the sandbox or would let a
// config run arbitrary scripts.
var ovpnDropRe = regexp.MustCompile(`(?i)^\s*(up|down|route-up|route-pre-down|ipchange|client-connect|client-disconnect|learn-address|tls-verify|auth-user-pass-verify|script-security|socks-proxy|socks-proxy-retry|http-proxy|http-proxy-option|http-proxy-retry|dev-node|block-outside-dns|register-dns|route-method|ip-win32|windows-driver|tap-sleep|daemon|log|log-append|status|management\S*|auth-retry|writepid|chroot|user|group|auth-user-pass|askpass|plugin|up-delay|up-restart|dhcp-release|dhcp-renew|service)(\s|$)`)

var ovpnInlineFileRe = regexp.MustCompile(`(?i)^\s*(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2|pkcs12|extra-certs|dh|crl-verify|secret)\s+(\S+)`)

var ovpnAuthRe = regexp.MustCompile(`(?im)^\s*auth-user-pass(\s|$)`)

func sanitizeOVPN(cfg string) (string, error) {
	var out strings.Builder
	sc := bufio.NewScanner(strings.NewReader(cfg))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	inBlock := ""
	hasRemote := false
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		t := strings.TrimSpace(line)
		if inBlock != "" {
			out.WriteString(line + "\n")
			if strings.EqualFold(t, "</"+inBlock+">") {
				inBlock = ""
			}
			continue
		}
		if strings.HasPrefix(t, "<") && strings.HasSuffix(t, ">") && !strings.HasPrefix(t, "</") {
			inBlock = strings.Trim(t, "<>")
			out.WriteString(line + "\n")
			continue
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if ovpnDropRe.MatchString(t) {
			continue
		}
		if m := ovpnInlineFileRe.FindStringSubmatch(t); m != nil && m[2] != "[inline]" {
			return "", fmt.Errorf(i18n.T("providers.configRefersToExternalFile"), m[2], m[1], m[1], m[1])
		}
		if strings.HasPrefix(strings.ToLower(t), "remote ") {
			hasRemote = true
		}
		out.WriteString(line + "\n")
	}
	if !hasRemote {
		return "", errors.New(i18n.T("providers.configHasNoRemoteLine"))
	}
	return out.String(), nil
}

func (openvpnProvider) Spec(c *config.Connection) (*bridge.ProcSpec, error) {
	cfg, err := sanitizeOVPN(c.S("config"))
	if err != nil {
		return nil, err
	}
	files := map[string]bridge.File{
		"client.ovpn": {Content: cfg},
		"up.sh":       {Content: "#!/bin/sh\nexec {{agent}} hook ovpn-up {{id}}\n", Mode: 0o700},
		"down.sh":     {Content: "#!/bin/sh\nexec {{agent}} hook ovpn-down {{id}}\n", Mode: 0o700},
	}
	argv := []string{"openvpn",
		"--config", "{{dir}}/client.ovpn",
		"--socks-proxy", "{{socksh}}", "{{socksp}}",
		"--script-security", "2",
		"--route-up", "{{dir}}/up.sh",
		"--down", "{{dir}}/down.sh",
		"--pull-filter", "ignore", "route-ipv6",
		"--pull-filter", "ignore", "ifconfig-ipv6",
		"--pull-filter", "ignore", "block-outside-dns",
		"--pull-filter", "ignore", "register-dns",
		"--auth-nocache",
		"--connect-retry-max", "3",
		"--verb", "3",
	}
	// Credentials, OTP / challenge codes and the key password are answered
	// over the management socket: nothing secret is written to disk and MFA
	// prompts reach the user.
	argv = append(argv,
		"--management", "{{dir}}/mgmt.sock", "unix",
		"--management-query-passwords",
		"--management-hold",
		"--auth-retry", "interact",
	)
	if c.P("username") != "" || ovpnAuthRe.MatchString(c.S("config")) {
		argv = append(argv, "--auth-user-pass")
	}
	ex, err := extraArgs(c.P("extraArgs"))
	if err != nil {
		return nil, err
	}
	argv = append(argv, ex...)
	return &bridge.ProcSpec{
		ID: c.ID, Name: c.Name, Argv: argv, Files: files,
		RouteAll:    boolDefault(c, "routeAll", true),
		FallbackDNS: dnsList(c),
		Reconnect:   boolDefault(c, "reconnect", true),
		// OpenVPN may run route-up before the TLS handshake (p2p/static
		// configs); trust only its own "completed" message.
		UpPattern:      `Initialization Sequence Completed`,
		DownPattern:    `SIGUSR1\[|SIGHUP\[|Restart pause|Inactivity timeout|AUTH_FAILED`,
		OpenVPNMgmt:    true,
		ReachedPattern: `Peer Connection Initiated|TLS: Initial packet from`,
		PendingPattern: `AUTH_PENDING|pending auth`,
		Creds:          &bridge.Creds{User: c.P("username"), Pass: c.S("password"), KeyPass: c.S("keyPassword"), MFA: c.P("mfaAnswer")},
	}, nil
}

var ovpnRemoteRe = regexp.MustCompile(`(?im)^\s*remote\s+(\S+)`)

func (openvpnProvider) ServerHosts(c *config.Connection) []string {
	var out []string
	for _, m := range ovpnRemoteRe.FindAllStringSubmatch(c.S("config"), -1) {
		out = append(out, m[1])
	}
	return out
}

func (openvpnProvider) Detect(filename, data string) bool {
	if strings.HasSuffix(strings.ToLower(filename), ".ovpn") {
		return true
	}
	return ovpnRemoteRe.MatchString(data) && (strings.Contains(data, "<ca>") || strings.Contains(strings.ToLower(data), "client"))
}

func (openvpnProvider) Import(filename, data string) (*config.Connection, error) {
	if _, err := sanitizeOVPN(data); err != nil {
		return nil, err
	}
	name := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	if name == "" || name == "." {
		name = "OpenVPN"
	}
	return &config.Connection{Name: name, Secrets: map[string]string{"config": data}, Params: map[string]string{}}, nil
}

// shellSplit splits a command line honouring simple quotes.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	has := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
			has = true
		case r == ' ' || r == '\t' || r == '\n':
			if cur.Len() > 0 || has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 || has {
		out = append(out, cur.String())
	}
	return out
}
