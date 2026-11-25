//go:build !windows

package wslhost

// BasePath is the folder WSL keeps a distro's disk in ("" when unknown).
func BasePath(name string) string { return "" }
