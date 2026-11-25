package app

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"vpner/internal/config"
	"vpner/internal/i18n"
)

// A VM with a VPN program VPNer set up (INCY) gets a DNS server of its own:
// Cloudflare over DoH, reached through that VM. Names of sites that go out
// directly are then resolved past the local network's DNS, which does not
// see them.
const vmDoH = "https://cloudflare-dns.com/dns-query"

// vmDNSID is the id of the DNS server VPNer adds for the VM connection id.
func vmDNSID(id string) string { return "dns-cf-" + id }

// withVMDNS adds the DNS server of the VM connection id (named name) to d,
// unless the user already reaches some DNS server through it, and makes it
// the default if the default was only the system DNS (the user has not chosen
// another). It reports whether d changed and whether the server became the
// default.
func withVMDNS(d *config.DNS, id, name string) (changed, isDefault bool) {
	for _, s := range d.Servers {
		if s.Via == id {
			return false, false
		}
	}
	sid := vmDNSID(id)
	if d.Server(sid) != nil {
		return false, false
	}
	d.Servers = append(d.Servers, config.DNSServer{
		ID: sid, Name: fmt.Sprintf(i18n.T("app.cloudflareViaConn"), name), Address: vmDoH, Via: id,
	})
	if len(d.Default) == 1 && d.Default[0] == config.DNSSystemID {
		d.Default = []string{sid}
		isDefault = true
	}
	return true, isDefault
}

// dohWorks asks the DNS server for a name through the HTTP proxy of a
// connection: the server is added only once it answers, so that a VM whose
// VPN does not pass traffic yet never leaves the computer without DNS.
func dohWorks(proxy string) error {
	c := clientVia(proxy)
	req, err := http.NewRequest("GET", vmDoH+"?name=cloudflare.com&type=A", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-json")
	resp, err := c.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			return ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"Status":0`) {
		return fmt.Errorf("%s: %.200s", resp.Status, b)
	}
	return nil
}
