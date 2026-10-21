# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-21

### Added

- Legal information in English and Russian (LEGAL.md): the open-source components inside VPNer and what their licenses require, the components VPNer downloads, trademarks, no warranty, limitation of liability, your responsibility and privacy with every network request VPNer makes.
- THIRD_PARTY_NOTICES.txt with the license texts of the built-in components: attached to releases, installed next to vpner.exe, included in the portable zip and built into vpner.exe (Settings → Legal, `vpner.exe licenses`).
- A short "as is" note in the installer.

## [0.1.0] - 2026-10-20

The first public beta.

### Added

- Routing of programs, sites, domains, subnets, site categories, countries, ports and protocols through several VPNs at once (the mihomo engine behind a TUN adapter), with a fail-closed default: rules leading to a VPN that is down block traffic.
- Built-in WireGuard and AmneziaWG (including 2.0), the Amnezia full access key (VPNer creates its own user on your server), VLESS/Reality, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, SOCKS5/HTTP and network interfaces.
- Cisco AnyConnect / Secure Client, GlobalProtect, Fortinet, Pulse/Ivanti, F5 (OpenConnect) and OpenVPN in isolated WSL network namespaces.
- Hyper-V virtual machines for original VPN apps, created and set up automatically.
- Saved passwords (DPAPI), MFA codes, push confirmations, SAML/SSO sign-in; corporate VPNs log in one at a time; idle sessions are kept alive; logins that were not confirmed in time are retried.
- DNS: DoH, DoH3, DoT, DoQ, UDP/TCP, the system resolver, servers reached through a VPN, per-domain DNS rules, FakeIP.
- Import of keys, configs, links, subscriptions, Clash/mihomo configs and VPNer profiles; profile export.
- Leak test, live connections, log, system kill switch (Windows Firewall), emergency network restore.
- Self-healing of stalled tunnels; engine processes end together with VPNer.
- Appearance: Standard, CLI / terminal and Glass themes in light and dark, own values and variables, per-connection colors, animations and effects that can be turned off one by one.
- English and Russian interface; texts in locale files.
- Installer with language and theme choice, uninstall, portable zip.
