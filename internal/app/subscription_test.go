package app

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// What VPNer sends for each way of introducing itself: a usual client sends
// no device code; "as INCY" sends the device code of the INCY app on this
// computer; "own" makes a device code once and keeps it.
func TestFetchSubscriptionAs(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	appdata := t.TempDir()
	t.Setenv("APPDATA", appdata)
	a := &App{DataDir: t.TempDir()}

	if _, _, err := a.FetchSubscription(srv.URL, SubAsClient); err != nil {
		t.Fatal(err)
	}
	if got.Get("x-hwid") != "" || got.Get("User-Agent") != "clash.meta/VPNer" {
		t.Fatalf("client: %v", got)
	}

	if _, _, err := a.FetchSubscription(srv.URL, SubAsIncy); err == nil {
		t.Fatal("no INCY on this computer, but no error")
	}
	os.MkdirAll(filepath.Join(appdata, "incy"), 0o700)
	os.WriteFile(filepath.Join(appdata, "incy", "hwid"), []byte("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\n"), 0o600)
	if _, _, err := a.FetchSubscription(srv.URL, SubAsIncy); err != nil {
		t.Fatal(err)
	}
	if got.Get("x-hwid") != "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" || got.Get("x-client") != "INCY" || got.Get("User-Agent") != "INCY/1.0 (Desktop)" {
		t.Fatalf("incy: %v", got)
	}

	if _, _, err := a.FetchSubscription(srv.URL, SubAsOwn); err != nil {
		t.Fatal(err)
	}
	own := got.Get("x-hwid")
	if own == "" || own == "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE" || len(own) != 36 {
		t.Fatalf("own code %q", own)
	}
	a.FetchSubscription(srv.URL, SubAsOwn) // again
	if got.Get("x-hwid") != own {
		t.Fatal("own device code changed: it would take one more place every time")
	}
}

// A placeholder instead of servers (one server on port 1) is recognised,
// as Clash YAML and as a link list; real servers are not.
func TestSubscriptionStub(t *testing.T) {
	clash := "proxies:\n  - name: Not supported\n    type: vless\n    server: stub.example.net\n    port: 1\n    uuid: 11111111-2222-3333-4444-555555555555\n    network: tcp\nproxy-groups:\n  - name: G\n    type: select\n    proxies: [Not supported]\nrules:\n  - MATCH,G\n"
	if !SubscriptionStub("subscription", clash) {
		t.Error("Clash placeholder not recognised")
	}
	links := base64.StdEncoding.EncodeToString([]byte("vless://11111111-2222-3333-4444-555555555555@stub.example.net:1?encryption=none&type=tcp&security=none#Not%20supported\n"))
	if !SubscriptionStub("subscription", links) {
		t.Error("link placeholder not recognised")
	}
	real := "vless://11111111-2222-3333-4444-555555555555@203.0.113.7:443?security=reality&sni=a.example&pbk=PUBKEY&sid=abcd&type=tcp#Server"
	if SubscriptionStub("subscription", real) {
		t.Error("a real server taken for a placeholder")
	}
}

// The title of a subscription comes from its Profile-Title header.
func TestSubTitle(t *testing.T) {
	if got := subTitle("base64:"+base64.StdEncoding.EncodeToString([]byte("Pepper VPN")), "h.example"); got != "Pepper VPN" {
		t.Errorf("base64 title: %q", got)
	}
	if got := subTitle("Plain", "h.example"); got != "Plain" {
		t.Errorf("plain title: %q", got)
	}
	if got := subTitle("", "h.example"); got != "h.example" {
		t.Errorf("no title: %q", got)
	}
}

// Servers imported from a subscription are marked with it; the link itself
// is never kept, only a hash of it.
func TestImportMarksSubscription(t *testing.T) {
	a := presetApp(t)
	link := "vless://11111111-2222-3333-4444-555555555555@203.0.113.9:443?security=reality&sni=a.example&pbk=PUBKEY&sid=abcd&type=tcp#One\nvless://11111111-2222-3333-4444-555555555555@203.0.113.10:443?security=reality&sni=a.example&pbk=PUBKEY&sid=abcd&type=tcp#Two"
	out, err := a.ImportData("subscription", link, false, ImportOptions{Source: "abc123", SourceName: "Pepper VPN"})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range out.IDs {
		c := a.Config().Conn(id)
		if c.P(ParamSub) != "abc123" || c.P(ParamSubName) != "Pepper VPN" {
			t.Fatalf("not marked: %+v", c.Params)
		}
	}
}
