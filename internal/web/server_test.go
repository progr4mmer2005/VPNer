package web

import (
	"os"
	"strings"
	"testing"

	"vpner/internal/app"
)

// The saved look is put into the page, safely escaped, so the window opens
// in its theme.
func TestPageLook(t *testing.T) {
	// not t.TempDir: the app keeps its log file open
	dir, err := os.MkdirTemp("", "vpner-web-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	a, err := app.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{App: a}
	if p := string(s.page()); !strings.Contains(p, "window.VPNER_LOOK = null;") || strings.Contains(p, "<!--vpner-look-->") {
		t.Fatal("no look placeholder replacement without a saved look")
	}
	if err := a.SaveAppearance([]byte(`{"theme":"cli","look":{"t":"cli","m":"dark","css":"--accent: #fff</script><script>alert(1)"}}`)); err != nil {
		t.Fatal(err)
	}
	p := string(s.page())
	if !strings.Contains(p, `window.VPNER_LOOK = {"t":"cli","m":"dark"`) {
		t.Error("look not injected")
	}
	if strings.Contains(p, "</script><script>alert(1)") {
		t.Error("look is not escaped")
	}
	if err := a.SaveAppearance([]byte(`{broken`)); err == nil {
		t.Error("invalid appearance accepted")
	}
}
