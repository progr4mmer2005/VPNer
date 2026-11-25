package agent

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The log is handed out from the offset VPNer has read up to; a file that
// got shorter (a new one) is handed out from the start.
func TestAppLog(t *testing.T) {
	dir := t.TempDir()
	h := appLog(dir)
	get := func(q string) (string, string) {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest("GET", "/applog?"+q, nil))
		b, _ := io.ReadAll(rec.Body)
		return string(b), rec.Header().Get("X-Log-Size")
	}
	if body, size := get("offset=0"); body != "" || size != "0" {
		t.Errorf("no log yet: %q size %s", body, size)
	}
	os.WriteFile(filepath.Join(dir, "incy.log"), []byte("one\ntwo\n"), 0o644)
	if body, size := get("offset=4"); body != "two\n" || size != "8" {
		t.Errorf("from offset 4: %q size %s", body, size)
	}
	if body, _ := get("offset=100"); body != "one\ntwo\n" {
		t.Errorf("an offset past the end means a new file: %q", body)
	}
	if body, _ := get("name=../../etc/passwd&offset=0"); body != "" {
		t.Errorf("only files of the log folder: %q", body)
	}
}
