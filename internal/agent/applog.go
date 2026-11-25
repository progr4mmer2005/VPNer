package agent

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// AppLogDir holds copies of the logs of the VPN program VPNer set up in the
// VM (INCY). The program writes them into the user's home, which the gateway
// cannot read (ProtectHome); the desktop session script copies them here, and
// the gateway hands them to VPNer, which shows them in its own log.
const AppLogDir = "/var/log/vpner-app"

// appLogMax is the most one request returns; the rest comes with the next.
const appLogMax = 256 << 10

// appLog returns the part of a program log from ?offset= on. X-Log-Size is the
// size of the whole file: smaller than the offset VPNer asked for means the
// program started a new file, and VPNer reads it from the start.
func appLog(dir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Query().Get("name"))
		if name == "" || name == "." || name == "/" {
			name = "incy.log"
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			w.Header().Set("X-Log-Size", "0")
			return // no log yet
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		off, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if off < 0 || off > st.Size() {
			off = 0
		}
		w.Header().Set("X-Log-Size", strconv.FormatInt(st.Size(), 10))
		w.Header().Set("X-Log-Offset", strconv.FormatInt(off, 10))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return
		}
		io.Copy(w, io.LimitReader(f, appLogMax))
	}
}
