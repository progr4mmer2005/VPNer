//go:build !windows

package engine

import (
	"os"
	"os/exec"
)

func hideWindow(cmd *exec.Cmd) {}

func tieToUs(p *os.Process) {}

// KillStray is only needed on Windows.
func KillStray(bin string) int { return 0 }
