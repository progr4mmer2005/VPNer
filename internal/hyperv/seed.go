//go:build windows

package hyperv

import (
	"vpner/internal/i18n"

	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SeedConfig holds the per-VM values baked into cloud-init.
type SeedConfig struct {
	ID          string
	Hostname    string
	LANIP       string
	WANMac      string // colon form
	LANMac      string
	GatewayUser string
	GatewayPass string
	ConsolePass string
	Desktop     bool
	FallbackDNS []string
	Agent       []byte // vpner-agent linux binary
	App         string // VPN program VPNer installs and sets up (AppIncy), "" for none
}

// killSwitchNFT confines the gateway user: it may only talk to the host on
// the LAN and send everything else through tunnel interfaces created by the
// VPN application. Its packets can never leave through the VM's uplink.
const killSwitchNFT = `table inet vpner_ks
delete table inet vpner_ks
table inet vpner_ks {
	chain out {
		type filter hook output priority filter; policy accept;
		meta skuid "vpnergw" oifname "lo" accept
		meta skuid "vpnergw" oifname "lan0" ip daddr %[1]s accept
		meta skuid "vpnergw" oifname { "wan0", "lan0" } drop
	}
	chain in {
		type filter hook input priority filter; policy accept;
		iifname "lan0" ip saddr != %[1]s drop
		iifname "lan0" meta nfproto ipv6 drop
	}
}
`

const gatewayUnit = `[Unit]
Description=VPNer gateway (SOCKS5 into this VM's VPN)
After=network-online.target
Wants=network-online.target

[Service]
User=vpnergw
ExecStartPre=+/usr/sbin/nft -f /etc/vpner/killswitch.nft
ExecStart=/opt/vpner/vpner-agent gateway /etc/vpner/gateway.json
Restart=always
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/srv/vpner-share

[Install]
WantedBy=multi-user.target
`

// readme is put on the VM desktop.
func readme() string { return i18n.T("hyperv.thisIsVpnerVirtualMachine") }

func yamlStr(s string) string {
	b, _ := json.Marshal(s) // JSON strings are valid YAML scalars
	return string(b)
}

func indent(s, pad string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = pad + lines[i]
	}
	return strings.Join(lines, "\n")
}

// WriteSeed writes the NoCloud files into dir.
func WriteSeed(dir string, c SeedConfig) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	gw, _ := json.MarshalIndent(map[string]any{
		"listen": c.LANIP, "hostIp": LANHost, "user": c.GatewayUser, "pass": c.GatewayPass,
		"fallbackDns": c.FallbackDNS, "shareDir": "/srv/vpner-share", "wanIface": "wan0", "lanIface": "lan0",
	}, "", "  ")

	meta := fmt.Sprintf("instance-id: vpner-%s\nlocal-hostname: %s\n", c.ID, c.Hostname)
	network := fmt.Sprintf(`version: 2
ethernets:
  wan0:
    match:
      macaddress: %q
    set-name: wan0
    dhcp4: true
    dhcp6: false
  lan0:
    match:
      macaddress: %q
    set-name: lan0
    dhcp4: false
    dhcp6: false
    link-local: []
    addresses: [%s/24]
`, c.WANMac, c.LANMac, c.LANIP)

	// Files of the setup (setup.go), the desktop and the app; the setup
	// itself runs in vpner-setup.service, retried until it succeeds.
	extra := []seedFile{
		{"/usr/local/sbin/vpner-setup", "0755", setupScript(c.Desktop, c.App)},
		{"/etc/systemd/system/vpner-setup.service", "0644", setupUnit},
	}
	if c.Desktop {
		extra = append(extra, desktopFiles()...)
	}
	appFileList, _, _ := appFiles(c.App)
	extra = append(extra, appFileList...)
	appFilesYAML := ""
	for _, f := range extra {
		appFilesYAML += fmt.Sprintf("  - path: %s\n    permissions: %q\n    content: |\n%s\n", f.Path, f.Mode, indent(f.Content, "      "))
	}

	user := fmt.Sprintf(`#cloud-config
hostname: %[1]s
manage_etc_hosts: true
ssh_pwauth: false
disable_root: true
users:
  - name: vpner
    gecos: VPNer
    shell: /bin/bash
    groups: [sudo, audio, video, netdev, plugdev]
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: false
  - name: vpnergw
    system: true
    shell: /usr/sbin/nologin
    homedir: /var/lib/vpnergw
chpasswd:
  expire: false
  users:
    - {name: vpner, password: %[2]s, type: text}
write_files:
  - path: /etc/vpner/killswitch.nft
    permissions: "0644"
    content: |
%[3]s
  - path: /etc/systemd/system/vpner-gateway.service
    permissions: "0644"
    content: |
%[4]s
  - path: /etc/vpner/README.txt
    permissions: "0644"
    content: |
%[5]s
  - path: /etc/vpner/gateway.json
    permissions: "0640"
    owner: root:vpnergw
    defer: true
    content: |
%[6]s
%[7]sruncmd:
  - [sh, -c, "mkdir -p /mnt/seed && (mount -L CIDATA /mnt/seed || mount -L cidata /mnt/seed) && install -D -m 0755 /mnt/seed/vpner-agent /opt/vpner/vpner-agent && umount /mnt/seed"]
  - [sh, -c, "systemctl disable --now ssh ssh.socket 2>/dev/null || true"]
  - [sh, -c, "systemctl daemon-reload && systemctl enable vpner-setup.service && systemctl start --no-block vpner-setup.service"]
`, c.Hostname, yamlStr(c.ConsolePass),
		indent(fmt.Sprintf(killSwitchNFT, LANHost), "      "),
		indent(gatewayUnit, "      "),
		indent(readme(), "      "),
		indent(string(gw), "      "),
		appFilesYAML)

	files := map[string][]byte{
		"meta-data":      []byte(meta),
		"network-config": []byte(network),
		"user-data":      []byte(user),
		"vpner-agent":    c.Agent,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}
