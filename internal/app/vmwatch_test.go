package app

import (
	"testing"
	"time"
)

// A VM whose tunnel passes nothing is restarted after vmDeadAfter, then
// less and less often, and after vmRestartMax restarts VPNer says once that
// it stops. Traffic passing again starts everything over.
func TestVMHealthStep(t *testing.T) {
	h := &vmHealth{}
	t0 := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	expect := func(now time.Time, ok, restart, giveUp bool) {
		t.Helper()
		r, g := h.step(now, ok)
		if r != restart || g != giveUp {
			t.Fatalf("at %v ok=%v: restart=%v giveUp=%v, want %v %v", now.Sub(t0), ok, r, g, restart, giveUp)
		}
	}
	expect(at(0), false, false, false)
	expect(at(2*time.Minute), false, false, false) // not long enough yet
	expect(at(3*time.Minute), false, true, false)  // 1st restart

	// fails again right after: the streak starts over, and the 2nd restart
	// waits vmRestartWait(1) after the 1st
	expect(at(4*time.Minute), false, false, false)
	expect(at(7*time.Minute), false, false, false) // 3 min of failing, but only 4 since the restart
	expect(at(8*time.Minute), false, true, false)  // 2nd restart, 5 min after the 1st

	expect(at(9*time.Minute), false, false, false)
	expect(at(20*time.Minute), false, false, false) // 12 min since, wait is 15
	expect(at(23*time.Minute), false, true, false)  // 3rd restart

	expect(at(24*time.Minute), false, false, false)
	expect(at(30*time.Minute), false, false, true) // gives up, once
	expect(at(60*time.Minute), false, false, false)
	expect(at(3*time.Hour), false, false, false)

	// it passes traffic again: all is forgotten
	expect(at(4*time.Hour), true, false, false)
	if h.restarts != 0 || h.gaveUp {
		t.Fatalf("not reset: %+v", h)
	}
	expect(at(4*time.Hour+time.Minute), false, false, false)
	expect(at(4*time.Hour+4*time.Minute), false, true, false)

	// while a restart runs, nothing is counted
	h.busy = true
	expect(at(5*time.Hour), false, false, false)
	expect(at(6*time.Hour), false, false, false)
}

func TestVMRestartWait(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 5 * time.Minute, 2: 15 * time.Minute, 3: 45 * time.Minute} {
		if got := vmRestartWait(n); got != want {
			t.Errorf("vmRestartWait(%d) = %v, want %v", n, got, want)
		}
	}
}
