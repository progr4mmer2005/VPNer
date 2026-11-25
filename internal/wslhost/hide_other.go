//go:build !windows

package wslhost

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
