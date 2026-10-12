// Package assets embeds the Linux agent binaries into vpner.exe so the WSL
// side can be installed and updated without any download.
package assets

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"runtime"
)

//go:embed agent
var files embed.FS

// Agent returns the vpner-agent binary for the given Linux architecture
// (defaults to the host architecture) and its SHA-256.
func Agent(arch string) ([]byte, string, error) {
	if arch == "" {
		arch = runtime.GOARCH
	}
	gz, err := files.ReadFile("agent/vpner-agent-linux-" + arch + ".gz")
	if err != nil {
		return nil, "", fmt.Errorf("в эту сборку не встроен агент для linux/%s — соберите программу через build.ps1", arch)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, "", err
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}
