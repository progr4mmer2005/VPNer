package app

import (
	"testing"
	"time"

	"vpner/internal/config"
	"vpner/internal/engine"
)

// A connection that does not come back is rebuilt less and less often, up to
// the maximum pause, and as before once it answers again.
func TestRecoverWait(t *testing.T) {
	for recovers, want := range []time.Duration{2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute} {
		if got := recoverWait(recovers); got != want {
			t.Errorf("recoverWait(%d) = %v, want %v", recovers, got, want)
		}
	}
	if recoverWait(100) != recoverPauseMax {
		t.Error("no upper bound")
	}
}

// A connection whose twin answered is moved to the other REALITY hello, and
// back again if the server changes its mind; other connections are left.
func TestToggleRealityHello(t *testing.T) {
	cfg := &config.Config{Connections: []config.Connection{
		{ID: "a", Type: "link"},
		{ID: "b", Type: "link", Params: map[string]string{engine.ParamRealityHello: engine.RealityHelloPQ, "x": "1"}},
		{ID: "c", Type: "link"},
	}}
	changed := toggleRealityHello(cfg, map[string]bool{"a": true, "b": true})
	if len(changed) != 2 {
		t.Fatalf("changed %d connections, want 2", len(changed))
	}
	if cfg.Conn("a").P(engine.ParamRealityHello) != engine.RealityHelloPQ {
		t.Error("a must move to the new hello")
	}
	if _, ok := cfg.Conn("b").Params[engine.ParamRealityHello]; ok || cfg.Conn("b").P("x") != "1" {
		t.Errorf("b must move back to the older hello and keep its other parameters: %v", cfg.Conn("b").Params)
	}
	if cfg.Conn("c").P(engine.ParamRealityHello) != "" {
		t.Error("c must stay as it was")
	}
}
