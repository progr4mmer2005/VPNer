//go:build linux

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const nsPrefix = "vpner-"

func nsName(id string) string { return nsPrefix + id }

func run(argv ...string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// createNetns builds an isolated namespace for one VPN connection.
//
// The namespace has NO interface leading anywhere except loopback and a dummy
// "blackhole" device carrying the default route (some daemons refuse to
// redirect the gateway when no default route exists). Packets sent to the
// dummy device are dropped by the kernel. The only way out is the tunnel
// interface the VPN daemon creates; the daemon itself reaches its server
// exclusively through the agent's SOCKS5 uplink on 127.0.0.1 inside the
// namespace. Leaking traffic around the tunnel is impossible by construction.
func createNetns(id string) error {
	ns := nsName(id)
	deleteNetns(id)
	if err := run("ip", "netns", "add", ns); err != nil {
		return err
	}
	steps := [][]string{
		{"ip", "-n", ns, "link", "set", "lo", "up"},
		{"ip", "-n", ns, "link", "add", "blackhole0", "type", "dummy"},
		{"ip", "-n", ns, "link", "set", "blackhole0", "up"},
		{"ip", "-n", ns, "addr", "add", "169.254.253.1/30", "dev", "blackhole0"},
		{"ip", "-n", ns, "route", "add", "default", "via", "169.254.253.2", "dev", "blackhole0", "metric", "4000"},
	}
	for _, s := range steps {
		if err := run(s...); err != nil {
			deleteNetns(id)
			return err
		}
	}
	// No IPv6 inside VPN namespaces: nothing can sneak out over v6.
	for _, k := range []string{"all", "default", "lo"} {
		run("ip", "netns", "exec", ns, "sysctl", "-qw", "net.ipv6.conf."+k+".disable_ipv6=1")
	}
	// Per-namespace resolv.conf: daemons resolve through the agent's stub,
	// which asks the host (never through the tunnel, never directly).
	etc := filepath.Join("/etc/netns", ns)
	os.MkdirAll(etc, 0o755)
	os.WriteFile(filepath.Join(etc, "resolv.conf"), []byte("nameserver 127.0.0.1\noptions timeout:3 attempts:2\n"), 0o644)
	os.WriteFile(filepath.Join(etc, "hosts"), []byte("127.0.0.1 localhost\n"), 0o644)
	return nil
}

func deleteNetns(id string) {
	ns := nsName(id)
	// kill anything still living inside
	if out, err := exec.Command("ip", "netns", "pids", ns).Output(); err == nil {
		for _, p := range strings.Fields(string(out)) {
			exec.Command("kill", "-9", p).Run()
		}
	}
	exec.Command("ip", "netns", "del", ns).Run()
	os.RemoveAll(filepath.Join("/etc/netns", ns))
}

func cleanupStaleNetns() {
	out, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.HasPrefix(f[0], nsPrefix) {
			deleteNetns(strings.TrimPrefix(f[0], nsPrefix))
		}
	}
}

// inNetns runs fn on an OS thread switched into the namespace of connection
// id. Sockets created inside fn stay bound to that namespace.
func inNetns(id string, fn func() error) error {
	runtime.LockOSThread()
	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer unix.Close(orig)
	target, err := unix.Open(filepath.Join("/run/netns", nsName(id)), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		runtime.UnlockOSThread()
		return fmt.Errorf("namespace for %s: %w", id, err)
	}
	defer unix.Close(target)
	if err := unix.Setns(target, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	ferr := fn()
	if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
		// Leave the thread locked: Go will terminate it instead of reusing a
		// thread stuck in the wrong namespace.
		return fmt.Errorf("restore netns: %v (fn: %v)", err, ferr)
	}
	runtime.UnlockOSThread()
	return ferr
}
