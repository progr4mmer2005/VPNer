package app

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
)

// Local ports VPNer listens on (engine API, SOCKS and mixed listeners) come
// from this range, below the Windows dynamic port range (49152–65535).
// Hyper-V and WinNAT reserve blocks of the dynamic range for themselves
// ("netsh int ipv4 show excludedportrange"), also after VPNer has picked its
// ports — and a reserved port cannot be bound: a UDP listener on it failed
// with "access forbidden", so UDP through a chain (all of AmneziaWG) never
// passed, and listeners failed to come back after a reload.
const (
	portLo = 20000
	portHi = 40000
)

// freePort returns a loopback port that is free for both TCP and UDP.
func freePort() (int, error) {
	for range 200 {
		if p := portLo + rand.IntN(portHi-portLo); portFree(p) {
			return p, nil
		}
	}
	// Unlikely: the whole range is busy. Take what the system offers, still
	// free for both protocols.
	for range 50 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if portFree(p) {
			return p, nil
		}
	}
	return 0, errors.New("no free local port for TCP and UDP")
}

// portFree reports whether a loopback port can be bound for TCP and UDP.
func portFree(p int) bool {
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	l, err := net.Listen("tcp4", addr)
	if err != nil {
		return false
	}
	defer l.Close()
	u, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return false
	}
	u.Close()
	return true
}
