# Legal information

**English** · [Русский](LEGAL.ru.md)

This page explains, in plain words, which third-party software VPNer contains or downloads, what their licenses require and what they do not, how VPNer meets those requirements, and the terms on which VPNer itself is offered: no warranty, limitation of liability, your responsibility, privacy and trademarks.

> [!NOTE]
> This is the author's good-faith description, not legal advice. If something here is wrong or missing, please write to **jackjackjackjack024@gmail.com** and it will be fixed.

## In brief

- VPNer is **free** and is provided **"as is", without any warranty**. The author is **not liable** for damage from its use.
- You decide which connections you use and are **responsible** for following the rules of your organization and the law.
- VPNer **collects nothing** and sends nothing to the author. The only network requests it makes on its own are listed [below](#network-requests-that-vpner-makes).
- The programs contain **8 open-source components** under permissive licenses (BSD, MIT, Apache-2.0, MPL-2.0). Their license texts ship with every copy in [`THIRD_PARTY_NOTICES.txt`](internal/legal/THIRD_PARTY_NOTICES.txt).
- The VPN engine **mihomo (GPL-3.0)** and Linux packages are **not included**: VPNer downloads them from their official sources on your computer, so they stay under their own licenses and do not affect VPNer's.
- Names like Cisco, OpenVPN or WireGuard only say what VPNer is **compatible with**. VPNer is not affiliated with these companies.

## Contents

1. [VPNer itself](#1-vpner-itself)
2. [Components built into VPNer](#2-components-built-into-vpner)
3. [Components that VPNer downloads](#3-components-that-vpner-downloads)
4. [Trademarks](#4-trademarks)
5. [No warranty](#5-no-warranty)
6. [Limitation of liability](#6-limitation-of-liability)
7. [Your responsibility](#7-your-responsibility)
8. [Privacy](#8-privacy)
9. [Changes and contact](#9-changes-and-contact)

## 1. VPNer itself

- **Using it.** You may download, install and use the published builds of VPNer free of charge, at home and at work, on as many computers as you like.
- **The code.** The source code is published so that anyone can review and test it. There is no open-source license yet, so all rights to the code stay with the author. Under the GitHub Terms of Service you can view the repository and fork it on GitHub. To reuse the code in your own project or to publish modified builds, ask the author first.
- **Donations** on Boosty are voluntary. They do not buy a license, support, features or any warranty and create no obligations for either side.
- VPNer was written by an AI model (Claude Opus 5.5) directed by the author. It is an **early beta that has not been audited** (see [Project status](README.md#project-status)).

## 2. Components built into VPNer

These components are compiled into `vpner.exe`, `vpner-setup.exe` and the Linux agent that `vpner.exe` carries inside. **None of them is modified.**

| Component | Version | License | What VPNer uses it for |
|---|---|---|---|
| [Go](https://go.dev) (standard library and runtime) | 1.27.2 | BSD-3-Clause + patent grant | everything: VPNer is written in Go |
| [fyne.io/systray](https://github.com/fyne-io/systray) | v1.12.2 | Apache-2.0 | the tray icon |
| [godbus/dbus](https://github.com/godbus/dbus) | v5.1.0 | BSD-2-Clause | a dependency of systray (not used on Windows, but compiled in) |
| [hashicorp/yamux](https://github.com/hashicorp/yamux) | v0.1.2 | MPL-2.0 | the channel between Windows and the WSL container |
| [ulikunitz/xz](https://github.com/ulikunitz/xz) | v0.5.17 | BSD-3-Clause | unpacking downloaded images |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | v0.58.0 | BSD-3-Clause + patent grant | SSH to your own Amnezia server |
| [golang.org/x/net](https://pkg.go.dev/golang.org/x/net) | v0.61.0 | BSD-3-Clause + patent grant | DNS inside the container |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | v0.49.0 | BSD-3-Clause + patent grant | Windows and Linux system calls |
| [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) | v3.0.1 | MIT and Apache-2.0 | the engine configuration |

The interface uses no third-party libraries, fonts or icons: the page, the icons and the logo are VPNer's own, and the fonts are the ones installed with Windows.

### What these licenses require, and how VPNer does it

| License | What it requires when a program is distributed | How VPNer does it |
|---|---|---|
| **BSD-2 / BSD-3** | Keep the copyright notice, the list of conditions and the disclaimer in the documentation of the program. BSD-3 also forbids using the authors' names to promote the program. | The full texts are in `THIRD_PARTY_NOTICES.txt`. VPNer never claims that these authors endorse it. |
| **MIT** | Include the copyright notice and the permission notice. | In `THIRD_PARTY_NOTICES.txt`. |
| **Apache-2.0** | Give a copy of the license; keep the content of the component's `NOTICE` file; mark files you changed. | The license and yaml.v3's `NOTICE` are in `THIRD_PARTY_NOTICES.txt`; nothing was changed. |
| **MPL-2.0** | When the program is given out in compiled form, tell people where to get the source code of the MPL files and do not restrict their rights to it. Changes to those files would have to be published under MPL-2.0. | yamux is used unmodified; `THIRD_PARTY_NOTICES.txt` contains its license and a link to its exact source code. |
| **Go patent grant** (`PATENTS`) | Nothing extra; it is a promise by Google not to sue users over patents in this code. | Included in `THIRD_PARTY_NOTICES.txt` for completeness. |

### What these licenses do *not* require

- **Opening VPNer's own source code** or putting VPNer under any particular license. All of these licenses are permissive. MPL-2.0 works per file and covers only yamux's own files, not the program that uses them.
- **Fees, registration or the authors' permission.**
- **Mentioning the components in the interface or in advertising.** Shipping the texts with the program is enough.
- **Keeping VPNer's code public.**

### Where the license texts are

- [`THIRD_PARTY_NOTICES.txt`](internal/legal/THIRD_PARTY_NOTICES.txt) is attached to every [release](../../releases).
- The installer puts it next to `vpner.exe` (`C:\Program Files\VPNer` by default). The portable zip has it next to `vpner.exe`.
- `vpner.exe` carries it inside: **Settings → Legal → Third-party licenses** or `vpner.exe licenses`. This matters because `vpner.exe` is also published on its own.
- In the repository it is generated from the license files of the modules (`go generate ./internal/legal`). A test fails if a module from `go.mod` has no license text there.

## 3. Components that VPNer downloads

These programs and data are **not part of VPNer's files**. When a feature needs one, VPNer downloads it on your computer from the official source. Each download is pinned to an exact version and checked by SHA-256/512, so you get exactly the official file.

| Component | License | Source | When |
|---|---|---|---|
| [mihomo](https://github.com/MetaCubeX/mihomo) v1.19.32, the routing engine | **GPL-3.0** | GitHub releases of MetaCubeX/mihomo | the first start |
| Rule databases (site categories, IP countries) | GPL-3.0 and the licenses of their sources | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat), downloaded by mihomo itself | only if your rules use site categories or countries |
| [Alpine Linux](https://alpinelinux.org) 3.24.2 (minirootfs) for the WSL container | various open-source licenses (MIT, GPL-2.0 and others) | dl-cdn.alpinelinux.org | the first connection that runs in WSL |
| Alpine packages: `openconnect` (LGPL-2.1), `openvpn` (GPL-2.0), `iproute2` (GPL-2.0) | as listed | Alpine repositories | when you add a connection of that type |
| [Debian](https://www.debian.org) 13 cloud image and packages (desktop, Firefox ESR, nftables…) for virtual machines | free licenses per the [Debian Free Software Guidelines](https://www.debian.org/social_contract#guidelines) | cloud.debian.org, Debian mirrors | when you create a virtual machine |
| VPN apps you install inside a virtual machine | the licenses of their vendors | wherever you get them | installed by you |

### Why VPNer's own terms are not affected

1. **VPNer does not distribute them.** They are not inside the installer, the zip or `vpner.exe`; each user's computer gets them straight from the official source, under that source's license. The duties of GPL and LGPL (a copy of the license, an offer of the source code) apply to whoever gives out copies, and the projects themselves meet them.
2. **VPNer runs them as separate programs.** It talks to them only through configuration files, command-line arguments and local network interfaces: mihomo's control API, the OpenVPN management interface, standard input and output. According to the [GPL FAQ](https://www.gnu.org/licenses/gpl-faq.html#MereAggregation), programs that communicate this way normally stay separate works, so the GPL of mihomo or OpenVPN does not extend to VPNer.
3. **Nothing is changed.** VPNer uses the official, unmodified builds.

### What would change this (the project's own rule)

The project never does any of the following, because each would bring GPL duties to VPNer:
- putting mihomo or another GPL/LGPL program into the installer or the zip (that would require shipping its license and offering its exact source code);
- modifying such a program (the changes would have to be published under the same license);
- compiling GPL-licensed Go code into `vpner.exe` (VPNer as a whole would then have to be GPL).

## 4. Trademarks

Cisco, AnyConnect and Cisco Secure Client are trademarks of Cisco Systems, Inc. GlobalProtect is a trademark of Palo Alto Networks, Inc. Fortinet and FortiGate are trademarks of Fortinet, Inc. Pulse Secure and Ivanti are trademarks of Ivanti, Inc. F5 and BIG-IP are trademarks of F5, Inc. OpenVPN is a trademark of OpenVPN Inc. WireGuard is a trademark of Jason A. Donenfeld. AmneziaVPN and AmneziaWG belong to the Amnezia project. Windows, Hyper-V, WSL, Microsoft Edge, Teams and Outlook are trademarks of Microsoft Corporation. Debian is a trademark of Software in the Public Interest, Inc. Other names belong to their owners.

These names are used **only to say which VPNs and systems VPNer works with**. VPNer is an independent project and is **not affiliated with, endorsed or sponsored by** any of these companies. VPNer contains no code of their clients: it connects through the open-source clients OpenConnect and OpenVPN and the built-in engine, or runs the original app that you install yourself in a virtual machine.

## 5. No warranty

VPNer is provided **"as is" and "as available", without warranty of any kind**, express or implied. This includes, without limitation, any warranty of merchantability, fitness for a particular purpose and non-infringement, and any warranty that VPNer will work without errors or interruptions, will be secure, will prevent traffic or DNS leaks, or will work with your VPN servers or your network.

VPNer is an early beta, written by an AI model and not audited. Test it before you rely on it, especially the leak protection and the kill switch.

## 6. Limitation of liability

To the maximum extent permitted by applicable law, **the author and contributors are not liable for any damage** arising from the use of VPNer or the inability to use it. This includes direct, indirect, incidental, special, consequential and exemplary damage, for example:
- loss of network access or of data;
- leaks of traffic, DNS queries or credentials;
- security incidents and interruptions of work or business;
- disciplinary, contractual or other consequences of breaking the rules of your organization or of a service.

This holds even if the author was told that such damage was possible. Where the law does not allow such an exclusion, liability is limited to the smallest extent the law allows. This is free software; using it means you accept these terms.

## 7. Your responsibility

- **Use only connections and accounts that you are allowed to use.** Corporate VPN accounts and their settings are governed by the policies of your organization.
- **Check your organization's rules.** Many organizations restrict running other VPNs or split routing (split tunneling) next to the corporate VPN, or require all traffic to go through it. Ask your IT or security team before using VPNer with work connections.
- **Follow the law** of your country and the terms of the services you connect to.
- **Protect your data.** Saved passwords and keys are encrypted for your Windows account. A profile exported *with* passwords is a plain file, so keep it safe.
- **Know what VPNer changes.** VPNer needs administrator rights. It adds a virtual network adapter, routes and DNS settings and Windows Firewall rules (the kill switch), and creates a WSL distribution named `vpner` and Hyper-V virtual machines when you use them. To undo:
  - `vpner.exe restore` or **Settings → Maintenance** returns the network;
  - uninstalling removes the program, and you can choose to delete the settings and the container as well.

## 8. Privacy

### What VPNer does not do

- No telemetry, analytics, crash reports, advertising, accounts or registration.
- No update checks.
- Nothing is sent to the author.

### What stays on your computer

- **Settings, connections, rules and logs:** `%LOCALAPPDATA%\VPNer`, or the `data` folder of the portable version. Passwords and keys are encrypted with Windows DPAPI, tied to your Windows account.
- **WSL container and virtual machines:** they are created on your computer only when you use them.
- **The window:** it is Microsoft Edge in app mode with its own separate profile. It shows only a page served by VPNer on `127.0.0.1`. Edge itself follows Microsoft's privacy statement.

### Network requests that VPNer makes

Besides the traffic of your own programs, which goes where your rules send it, VPNer makes only these requests:

| Address | When | Why | What the other side sees |
|---|---|---|---|
| github.com (release files) | the first start | to download the mihomo engine | your IP address and a normal download request |
| github.com (MetaCubeX/meta-rules-dat), by mihomo | only if your rules use site categories or countries | to download the rule databases | the same |
| dl-cdn.alpinelinux.org | the first WSL connection; adding a WSL connection type | the container image and its packages | the same |
| cloud.debian.org and Debian mirrors | creating a virtual machine | the image and its packages | the same |
| cp.cloudflare.com/generate_204 | every 10 seconds while routing is on, through each built-in connection | to notice a stalled tunnel and rebuild it | an empty request coming from that VPN's exit address |
| 1.1.1.1 and 2606:4700:4700::1111 (`/cdn-cgi/trace`) | only when you run the **Leak test** | to show the real exit IP of each connection | a request from each connection's exit address |
| your DNS servers | while routing is on | name resolution; the default is your network's own DNS | the names being resolved |
| the DNS server inside an OpenConnect tunnel (`www.msftncsi.com`) | every 60 seconds | to keep an idle corporate session alive | one DNS query inside your organization's network |
| your VPN servers and your Amnezia server (SSH with your key) | when you connect, or when you add an Amnezia full access key | the connections you added | what any VPN client sends |

### Third parties

- **Download and probe services.** GitHub, Alpine, Debian and Cloudflare see your IP address when files are downloaded or probes run, as with any download. Their own privacy policies apply.
- **Donations.** If you donate on Boosty, Boosty's policy applies. The author sees only what Boosty shows: the name you choose and your message.
- **Contacting the author.** If you write to the author by email or in an issue, your message is used only to answer it.

## 9. Changes and contact

This page may be updated together with VPNer; the current version is always in the repository, and changes are noted in the [changelog](CHANGELOG.md). Questions: **jackjackjackjack024@gmail.com**. Security problems: see [SECURITY.md](SECURITY.md).
