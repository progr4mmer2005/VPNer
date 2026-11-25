//go:build windows

package winutil

import "golang.org/x/sys/windows"

var procDnsFlushResolverCache = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// FlushDNS clears the Windows DNS cache (like "ipconfig /flushdns").
func FlushDNS() {
	if procDnsFlushResolverCache.Find() == nil {
		procDnsFlushResolverCache.Call()
	}
}
