package app

import "net"

// hasIPv6 reports whether the computer has global IPv6 connectivity.
func hasIPv6() bool {
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Name == "VPNer" {
			continue
		}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			ip := ipn.IP
			if ip[0]&0xfe == 0xfc { // unique local fc00::/7
				continue
			}
			if ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0 && ip[3] == 0 { // Teredo
				continue
			}
			return true
		}
	}
	return false
}
