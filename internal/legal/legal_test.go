package legal

import (
	"os"
	"strings"
	"testing"
)

// Every module of go.mod must have its license in the notices: a new
// dependency without one fails here.
func TestEveryModuleHasNotice(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "require "))
		if len(f) < 2 || !strings.HasPrefix(f[1], "v") || !strings.Contains(f[0], ".") {
			continue
		}
		n++
		if !strings.Contains(Notices, "\n"+f[0]+"\n") || !strings.Contains(Notices, "  - "+f[0]+" "+f[1]+" ") {
			t.Errorf("%s %s is not in %s: run the notices generator and add its license", f[0], f[1], FileName)
		}
	}
	if n == 0 {
		t.Fatal("no modules found in go.mod")
	}
	for _, s := range []string{"\nGo\n", "AS IS", "PATENTS"} {
		if !strings.Contains(Notices, s) {
			t.Errorf("notices miss %q", s)
		}
	}
}
