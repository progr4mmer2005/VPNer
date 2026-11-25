package agent

import (
	"testing"
	"time"
)

func TestSetupState(t *testing.T) {
	for _, tc := range []struct {
		in, state, code string
		ok              bool
	}{
		{"running\n", "running", "", true},
		{"done\n", "done", "", true},
		{"error app-download\n", "error", "app-download", true},
		{"", "", "", false}, // a VM made before 0.3.2: cloud-init tells
	} {
		st, code, ok := setupState(tc.in)
		if st != tc.state || code != tc.code || ok != tc.ok {
			t.Errorf("%q: got %q %q %v", tc.in, st, code, ok)
		}
	}
}

func TestDpkgStep(t *testing.T) {
	since := time.Date(2026, 11, 12, 21, 35, 0, 0, time.Local)
	log := `2026-10-01 02:10:00 status installed base-files:amd64 13.8
2026-11-12 21:39:58 install xfce4-panel:amd64 <none> 4.18.4-1
2026-11-12 21:40:01 status unpacked xfce4-panel:amd64 4.18.4-1
2026-11-12 21:40:01 status half-configured xfce4-panel:amd64 4.18.4-1
2026-11-12 21:40:02 startup packages configure
`
	if got := dpkgStep(log, since); got != "xfce4-panel" {
		t.Errorf("got %q, want xfce4-panel", got)
	}
	// only entries of the image build: nothing to show yet
	if got := dpkgStep("2026-10-01 02:10:00 status installed base-files:amd64 13.8\n", since); got != "" {
		t.Errorf("an entry from before the setup: got %q", got)
	}
	if got := dpkgStep("", since); got != "" {
		t.Errorf("empty log: got %q", got)
	}
	if got := dpkgStep("2026-11-12 21:41:00 install incy:amd64 <none> 3.9.0\n", since); got != "incy" {
		t.Errorf("got %q, want incy", got)
	}
}
