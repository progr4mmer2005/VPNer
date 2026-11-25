package app

import (
	"testing"

	"vpner/internal/amnezia"
	"vpner/internal/config"
	"vpner/internal/engine"
)

// The XRay hop is made once per Amnezia server connection: off, marked with
// that connection, with the new REALITY hello when the server needs it. A
// second setup only renews the link and keeps what the user changed.
func TestUpsertXRayHop(t *testing.T) {
	cfg := &config.Config{Connections: []config.Connection{
		{ID: "amn", Name: "Home", Type: "amnezia-server", Enabled: true},
		{ID: "other", Type: "link", Params: map[string]string{ParamXRayOf: "someone-else"}},
	}}
	amn := cfg.Conn("amn")
	c := UpsertXRayHop(cfg, amn, &amnezia.XRayLink{Link: "vless://one", NewHello: true})
	if len(cfg.Connections) != 3 {
		t.Fatalf("connections = %d, want 3", len(cfg.Connections))
	}
	if c.Type != "link" || c.Enabled || c.Name != "Home · XRay" || c.P(ParamXRayOf) != "amn" ||
		c.P(engine.ParamRealityHello) != engine.RealityHelloPQ || c.S("link") != "vless://one" {
		t.Fatalf("new hop = %+v", c)
	}
	id := c.ID

	// the user renames it and picks the other hello
	c.Name = "Mine"
	delete(c.Params, engine.ParamRealityHello)

	c = UpsertXRayHop(cfg, cfg.Conn("amn"), &amnezia.XRayLink{Link: "vless://two", NewHello: true})
	if len(cfg.Connections) != 3 || c.ID != id {
		t.Fatalf("second setup added a connection: %d, id %s → %s", len(cfg.Connections), id, c.ID)
	}
	if c.Name != "Mine" || c.P(engine.ParamRealityHello) != "" || c.S("link") != "vless://two" {
		t.Fatalf("updated hop = %+v", c)
	}
	if o := cfg.Conn("other"); o.S("link") != "" {
		t.Fatalf("someone else's hop touched: %+v", o)
	}
}
