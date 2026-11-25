// Command gen writes ../THIRD_PARTY_NOTICES.txt from the license files in the
// Go module cache. Run it after changing go.mod:
//
//	go generate ./internal/legal
//
// A new module also needs a line in mods below (TestEveryModuleHasNotice
// fails until it has one).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mod struct{ path, version, license, usedIn, source string }

var mods = []mod{
	{"fyne.io/systray", "v1.12.2", "Apache-2.0", "vpner.exe (tray icon)", "https://github.com/fyne-io/systray/tree/v1.12.2"},
	{"github.com/godbus/dbus/v5", "v5.1.0", "BSD-2-Clause", "vpner.exe (dependency of systray)", "https://github.com/godbus/dbus/tree/v5.1.0"},
	{"github.com/hashicorp/yamux", "v0.1.2", "MPL-2.0", "vpner.exe, vpner-setup.exe, Linux agent (Windows <-> WSL bridge)", "https://github.com/hashicorp/yamux/tree/v0.1.2"},
	{"github.com/ulikunitz/xz", "v0.5.17", "BSD-3-Clause", "vpner.exe, vpner-setup.exe (unpacking images)", "https://github.com/ulikunitz/xz/tree/v0.5.17"},
	{"golang.org/x/crypto", "v0.58.0", "BSD-3-Clause", "vpner.exe, vpner-setup.exe (SSH to your Amnezia server)", "https://cs.opensource.google/go/x/crypto/+/refs/tags/v0.58.0"},
	{"golang.org/x/net", "v0.61.0", "BSD-3-Clause", "Linux agent (DNS)", "https://cs.opensource.google/go/x/net/+/refs/tags/v0.61.0"},
	{"golang.org/x/sys", "v0.49.0", "BSD-3-Clause", "vpner.exe, vpner-setup.exe, Linux agent (system calls)", "https://cs.opensource.google/go/x/sys/+/refs/tags/v0.49.0"},
	{"gopkg.in/yaml.v3", "v3.0.1", "MIT and Apache-2.0", "vpner.exe, vpner-setup.exe (engine configuration)", "https://github.com/go-yaml/yaml/tree/v3.0.1"},
}

const header = `VPNer - third-party notices
%[1]s

VPNer is provided "AS IS", without warranty of any kind. See LEGAL.md in the
repository (https://github.com/progr4mmer2005/VPNer/blob/main/LEGAL.md) for
the full legal information: warranty disclaimer, limitation of liability,
privacy and trademarks.

The programs of VPNer (vpner.exe, vpner-setup.exe and the Linux agent that
vpner.exe carries inside) are built with Go and contain the open-source
components listed below, all of them UNMODIFIED. Their licenses allow this
use; each of them asks that its copyright notice and license text travel
with the program, and that is what this file is for.

Components that VPNer downloads while it runs (the mihomo engine, Alpine
Linux and its packages, Debian, rule databases) are NOT part of these files;
they come from their official sources under their own licenses - see
LEGAL.md.

Contents
`

func main() {
	cache, root := goEnv("GOMODCACHE"), goEnv("GOROOT")
	rule := strings.Repeat("=", 78)
	var b strings.Builder
	fmt.Fprintf(&b, header, rule)
	b.WriteString("  - Go (the Go programming language, standard library and runtime)  BSD-3-Clause\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "  - %s %s  %s\n", m.path, m.version, m.license)
	}
	b.WriteString("\n")
	section := func(title string, meta [][2]string, dir string) {
		fmt.Fprintf(&b, "%s\n%s\n%s\n", rule, title, rule)
		for _, kv := range meta {
			fmt.Fprintf(&b, "%-9s %s\n", kv[0]+":", kv[1])
		}
		found := false
		for _, f := range []string{"LICENSE", "NOTICE", "PATENTS"} {
			data, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil {
				continue
			}
			found = true
			text := strings.TrimRight(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n\t ")
			fmt.Fprintf(&b, "\n----- %s -----\n\n%s\n", f, text)
		}
		if !found {
			fail("no license file in " + dir)
		}
		b.WriteString("\n")
	}
	section("Go", [][2]string{{"License", "BSD-3-Clause"}, {"Used in", "all programs (standard library and runtime)"}, {"Source", "https://go.dev/doc/install/source"}}, root)
	for _, m := range mods {
		meta := [][2]string{{"Version", m.version}, {"License", m.license}, {"Used in", m.usedIn}, {"Source", m.source}}
		if m.license == "MPL-2.0" {
			meta = append(meta, [2]string{"Note", "used unmodified; its Source Code Form is available at the address above"})
		}
		section(m.path, meta, filepath.Join(cache, filepath.FromSlash(m.path)+"@"+m.version))
	}
	if err := os.WriteFile("THIRD_PARTY_NOTICES.txt", []byte(b.String()), 0o644); err != nil {
		fail(err.Error())
	}
}

func goEnv(k string) string {
	out, err := exec.Command("go", "env", k).Output()
	if err != nil {
		fail("go env " + k + ": " + err.Error())
	}
	return strings.TrimSpace(string(out))
}

func fail(s string) {
	fmt.Fprintln(os.Stderr, "gen:", s)
	os.Exit(1)
}
