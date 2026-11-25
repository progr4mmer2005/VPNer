//go:build windows

package hyperv

import (
	"fmt"
	"strings"

	"vpner/internal/i18n"
)

// The VM setup (packages, desktop, VPN program) runs in a script of its own,
// vpner-setup, started by a systemd unit rather than by cloud-init directly:
//
//   - it is retried by itself (10 minutes after a failure, and at every boot)
//     until it has succeeded once, so a step that failed because the network
//     was slow or apt was busy does not leave the VM half set up for good;
//   - it writes its state to SetupStateFile, which the gateway agent reports
//     to VPNer, so a failure is shown with its reason instead of being lost
//     when cloud-init forgets it at the next boot.
//
// Lessons from Debian 13 on Hyper-V, each of which broke the setup before:
//   - packages are installed only if the repository has them: one missing
//     name (policykit-1 is gone in Debian 13) made apt install nothing;
//   - apt waits for the dpkg lock: unattended-upgrades holds it at first boot;
//   - files go to directories that may not exist yet (write_files makes them);
//   - Xorg needs a Device section for the Hyper-V video card and no vga16fb.

// SetupStateFile holds "running", "done" or "error <code>" (SetupErr*).
const SetupStateFile = "/var/lib/vpner/setup-state"

// Setup error codes, reported by the agent and shown by VPNer.
const (
	SetupErrPackages    = "packages"     // base packages (network, apt)
	SetupErrGateway     = "gateway"      // the VPNer gateway service
	SetupErrDesktop     = "desktop"      // desktop packages or the display manager
	SetupErrAppPackages = "app-packages" // packages the VPN program needs
	SetupErrAppDownload = "app-download" // the VPN program could not be downloaded
	SetupErrAppInstall  = "app-install"  // the VPN program could not be installed
)

// desktopPackages is the desktop of a VM. Names must exist in Debian 13;
// TestDesktopPackages keeps known removed ones out.
var desktopPackages = []string{
	"xfce4", "xfce4-terminal", "xfce4-whiskermenu-plugin", "thunar", "mousepad",
	"lightdm", "lightdm-gtk-greeter", "firefox-esr", "firefox-esr-l10n-ru", "dbus-x11",
	"xserver-xorg-core", "xserver-xorg-input-libinput", "fonts-dejavu", "fonts-noto-color-emoji",
	"xdg-utils", "polkitd", "pkexec", "gvfs", "file-roller",
}

// desktopFiles configure the desktop; written by cloud-init, which creates
// their directories (lightdm.conf.d and xorg.conf.d do not exist on Debian 13).
func desktopFiles() []seedFile {
	return []seedFile{
		{"/etc/lightdm/lightdm.conf.d/50-vpner.conf", "0644", "[Seat:*]\nautologin-user=vpner\nautologin-session=xfce\n"},
		{"/etc/default/keyboard", "0644", "XKBLAYOUT=\"us,ru\"\nXKBOPTIONS=\"grp:alt_shift_toggle\"\n"},
		// The Hyper-V video card is not a PCI device: without this section
		// Xorg drops its only screen ("Cannot run in framebuffer mode").
		{"/etc/X11/xorg.conf.d/10-vpner-hyperv.conf", "0644",
			"Section \"Device\"\n  Identifier \"HyperV\"\n  Driver \"modesetting\"\n  Option \"kmsdev\" \"/dev/dri/card0\"\nEndSection\n"},
		// vga16fb is a second framebuffer next to hyperv_drm, which confuses
		// Xorg; it is also unloaded before the display manager starts, since
		// at the first boot it is already loaded.
		{"/etc/modprobe.d/vpner-hyperv-video.conf", "0644", "blacklist vga16fb\n"},
		{"/etc/systemd/system/lightdm.service.d/vpner.conf", "0644",
			"[Service]\nExecStartPre=-/usr/sbin/rmmod vga16fb vgastate\n"},
	}
}

// setupUnit runs the setup until it has succeeded once.
const setupUnit = `[Unit]
Description=VPNer: set up this VM (retried until it succeeds)
After=network-online.target cloud-final.service
Wants=network-online.target
ConditionPathExists=!/var/lib/vpner/setup-ok

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/vpner-setup
Restart=on-failure
RestartSec=10min
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
`

// setupScript builds /usr/local/sbin/vpner-setup for a VM.
func setupScript(desktop bool, app string) string {
	var b strings.Builder
	b.WriteString(`#!/bin/sh
# VPNer: sets up this VM. Run by vpner-setup.service until it succeeds once.
set -u
S=/var/lib/vpner
mkdir -p "$S"
exec 9>/run/vpner-setup.lock
flock -n 9 || exit 0
state() { printf '%s\n' "$*" > "$S/setup-state.tmp" && chmod 644 "$S/setup-state.tmp" && mv "$S/setup-state.tmp" "` + SetupStateFile + `"; }
fail() { echo "vpner: setup failed: $1" >&2; state "error $1"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -o DPkg::Lock::Timeout=1800 -o Acquire::Retries=5"
# pkgs installs the packages the repository has: a name that is gone (renamed
# in a new Debian) is reported, not a reason to install nothing.
pkgs() {
  ok=""
  for p in "$@"; do
    if apt-cache show "$p" >/dev/null 2>&1; then ok="$ok $p"; else echo "vpner: package $p is not in the repository, skipped" >&2; fi
  done
  [ -z "$ok" ] && return 0
  for i in 1 2 3 4 5; do
    $APT install -y --no-install-recommends $ok && return 0
    sleep 20
    $APT update || true
  done
  return 1
}
state running
updated=""
for i in 1 2 3 4 5; do $APT update && { updated=1; break; }; sleep 20; done
[ -n "$updated" ] || fail ` + SetupErrPackages + `
pkgs nftables locales || fail ` + SetupErrPackages + `
mkdir -p /srv/vpner-share && chown vpnergw:vpner /srv/vpner-share && chmod 2775 /srv/vpner-share
install -d -o vpner -g vpnergw -m 2750 ` + appLogDir + `
systemctl daemon-reload && systemctl enable --now vpner-gateway || fail ` + SetupErrGateway + `
sed -i 's/^# *ru_RU.UTF-8/ru_RU.UTF-8/' /etc/locale.gen && locale-gen && update-locale LANG=ru_RU.UTF-8 || true
`)
	if desktop {
		fmt.Fprintf(&b, `pkgs %s || fail %s
[ -x /usr/sbin/lightdm ] || fail %s
mkdir -p /home/vpner/Desktop && ln -sfn /srv/vpner-share '/home/vpner/Desktop/%s' && cp /etc/vpner/README.txt /home/vpner/Desktop/README.txt && chown -R vpner:vpner /home/vpner
systemctl set-default graphical.target
systemctl daemon-reload
systemctl reset-failed lightdm 2>/dev/null || true
systemctl restart lightdm || true
`, strings.Join(desktopPackages, " "), SetupErrDesktop, SetupErrDesktop, i18n.T("hyperv.filesFolder"))
	}
	// The app is installed after the desktop: it needs it, and its session
	// script waits until the app is there.
	if _, appPkgs, install := appFiles(app); install != "" {
		fmt.Fprintf(&b, `pkgs %s || fail %s
%s
rc=$?
[ $rc -eq 2 ] && fail %s
[ $rc -eq 0 ] || fail %s
`, strings.Join(appPkgs, " "), SetupErrAppPackages, install, SetupErrAppDownload, SetupErrAppInstall)
	}
	b.WriteString(`state done
touch "$S/setup-ok"
`)
	return b.String()
}
