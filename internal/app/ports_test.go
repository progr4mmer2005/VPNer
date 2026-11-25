package app

import (
	"fmt"
	"net"
	"testing"
)

// Ports come from below the Windows dynamic range, which Hyper-V reserves
// blocks of, and are free for UDP as well as TCP.
func TestFreePort(t *testing.T) {
	for range 20 {
		p, err := freePort()
		if err != nil {
			t.Fatal(err)
		}
		if p < portLo || p >= portHi {
			t.Fatalf("port %d outside %d–%d", p, portLo, portHi)
		}
		u, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatalf("port %d is not free for UDP: %v", p, err)
		}
		u.Close()
	}
}

// A port busy for UDP only is not offered.
func TestPortFreeChecksUDP(t *testing.T) {
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if portFree(u.LocalAddr().(*net.UDPAddr).Port) {
		t.Error("a port taken for UDP was reported free")
	}
}
