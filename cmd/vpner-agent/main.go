//go:build linux

// vpner-agent is the Linux half of VPNer. It runs inside the dedicated WSL
// distro (and, in gateway mode, inside VPN virtual machines).
package main

import (
	"fmt"
	"os"

	"vpner/internal/agent"
	"vpner/internal/i18n"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: vpner-agent serve | gateway <config.json> | hook <kind> <id> [args] | version")
		os.Exit(2)
	}
	// set by the host (wslhost) and inherited by hooks
	i18n.SetLang(i18n.Resolve(os.Getenv("VPNER_LANG")))
	var err error
	switch os.Args[1] {
	case "serve":
		err = agent.Serve()
	case "hook":
		if len(os.Args) < 4 {
			err = fmt.Errorf("usage: vpner-agent hook <kind> <id> [args]")
			break
		}
		err = agent.Hook(os.Args[2], os.Args[3], os.Args[4:])
	case "gateway":
		if len(os.Args) < 3 {
			err = fmt.Errorf("usage: vpner-agent gateway <config.json>")
			break
		}
		err = agent.Gateway(os.Args[2])
	case "version":
		fmt.Println(agent.Version)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpner-agent:", err)
		os.Exit(1)
	}
}
