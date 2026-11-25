package app

import (
	"strings"
	"testing"
	"time"
)

func TestSetupDetail(t *testing.T) {
	now := time.Date(2026, 11, 12, 21, 50, 0, 0, time.UTC)
	start := now.Add(-17 * time.Minute)
	d := setupDetail("base", start, now, "xfce4-panel", false)
	if p := strings.Split(d, " · "); len(p) != 3 || p[0] != "base" || !strings.Contains(p[1], "17") || !strings.Contains(p[2], "xfce4-panel") {
		t.Errorf("got %q", d)
	}
	if d := setupDetail("base", time.Time{}, now, "", false); d != "base" {
		t.Errorf("a VM already set up shows no time: %q", d)
	}
	if d := setupDetail("base", now, now, "", true); len(strings.Split(d, " · ")) != 3 {
		t.Errorf("stuck setup must say so: %q", d)
	}
}

func TestSetupStuck(t *testing.T) {
	now := time.Now()
	start := now.Add(-20 * time.Minute)
	if setupStuck(start, now.Add(-5*time.Minute), now, "xfce4") {
		t.Error("a package for 5 minutes is not stuck")
	}
	if !setupStuck(start, now.Add(-16*time.Minute), now, "xfce4") {
		t.Error("the same package for 16 minutes is stuck")
	}
	if setupStuck(start, now, now, "") {
		t.Error("an old agent: 20 minutes of setup are fine")
	}
	if !setupStuck(now.Add(-41*time.Minute), now, now, "") {
		t.Error("an old agent: 41 minutes of setup look stuck")
	}
	if setupStuck(time.Time{}, now.Add(-time.Hour), now, "x") {
		t.Error("a VM that is set up is never stuck")
	}
}
