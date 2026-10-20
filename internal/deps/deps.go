// Package deps downloads, verifies and installs everything VPNer needs:
// the mihomo routing engine and the dedicated WSL distro with VPN packages.
// Every download is pinned to an exact version and SHA-256.
package deps

import (
	"vpner/internal/i18n"

	"archive/zip"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Artifact struct {
	Name   string
	URL    string
	SHA256 string
	SHA512 string // used instead of SHA256 when set (e.g. Debian publishes SHA512 only)
	File   string // local file name in the downloads cache
}

func (a Artifact) sum() (string, bool) {
	if a.SHA512 != "" {
		return a.SHA512, true
	}
	return a.SHA256, false
}

const DebianRelease = "20261001-2618"

// DebianCloud is the image for VPN virtual machines (cloud-init, NoCloud).
func DebianCloud() (Artifact, error) {
	arch, sum := "", ""
	switch runtime.GOARCH {
	case "amd64":
		arch, sum = "amd64", "b8f1dce59d902d78375b214a40bc2483f07ca7acc0cd6e5270ea2afeafe623a2959664a449207ae3c34fa91baa228443f9dce6039048fd439a0c67d35875ac7b"
	case "arm64":
		arch, sum = "arm64", "cb80554bf05aa9eb42d0b99a9a395fefad04edc8435514c5387e32f4da83b7827c34809f6249b365dedacd3f0688580f2957fd13b388639c987058bbe127fa8d"
	default:
		return Artifact{}, fmt.Errorf(i18n.T("deps.architectureIsNotSupported"), runtime.GOARCH)
	}
	f := "debian-13-generic-" + arch + "-" + DebianRelease + ".tar.xz"
	return Artifact{Name: "Debian 13", File: f, SHA512: sum,
		URL: "https://cloud.debian.org/images/cloud/trixie/" + DebianRelease + "/" + f}, nil
}

const MihomoVersion = "v1.19.32"

const AlpineVersion = "3.24.2"

func Mihomo() (Artifact, error) {
	switch runtime.GOARCH {
	case "amd64":
		f := "mihomo-windows-amd64-compatible-" + MihomoVersion + ".zip"
		return Artifact{Name: "mihomo " + MihomoVersion, File: f,
			URL:    "https://github.com/MetaCubeX/mihomo/releases/download/" + MihomoVersion + "/" + f,
			SHA256: "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"}, nil
	case "arm64":
		f := "mihomo-windows-arm64-" + MihomoVersion + ".zip"
		return Artifact{Name: "mihomo " + MihomoVersion, File: f,
			URL:    "https://github.com/MetaCubeX/mihomo/releases/download/" + MihomoVersion + "/" + f,
			SHA256: "7a4f6e58af9a120920935f2150cf642d945085fdb3e753314505b334234e1d1e"}, nil
	}
	return Artifact{}, fmt.Errorf(i18n.T("deps.architectureIsNotSupported"), runtime.GOARCH)
}

func Alpine() (Artifact, error) {
	arch, sum := "", ""
	switch runtime.GOARCH {
	case "amd64":
		arch, sum = "x86_64", "c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677"
	case "arm64":
		arch, sum = "aarch64", "9bf70a7f18ea44094cbb5f70c58f9af129c8214745743db0e68e5502cc2ce773"
	default:
		return Artifact{}, fmt.Errorf(i18n.T("deps.architectureIsNotSupported"), runtime.GOARCH)
	}
	f := "alpine-minirootfs-" + AlpineVersion + "-" + arch + ".tar.gz"
	minor := AlpineVersion[:strings.LastIndex(AlpineVersion, ".")]
	return Artifact{Name: "Alpine Linux " + AlpineVersion, File: f, SHA256: sum,
		URL: "https://dl-cdn.alpinelinux.org/alpine/v" + minor + "/releases/" + arch + "/" + f}, nil
}

// Progress reports download progress; total may be -1 when unknown.
type Progress func(stage string, done, total int64)

// Fetch returns a verified local copy of an artifact, downloading it if
// needed. A correct file placed manually in the cache directory is used as is
// (offline installation).
func Fetch(a Artifact, cacheDir string, progress Progress) (string, error) {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(cacheDir, a.File)
	want, big := a.sum()
	if ok, _ := verify(dst, want, big); ok {
		return dst, nil
	}
	tmp := dst + ".part"
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		lastErr = download(a, tmp, progress)
		if lastErr == nil {
			break
		}
		time.Sleep(time.Duration(attempt) * 2 * time.Second)
	}
	if lastErr != nil {
		os.Remove(tmp)
		return "", fmt.Errorf(i18n.T("deps.couldNotDownloadYouCan"), a.Name, lastErr, a.URL, cacheDir)
	}
	ok, sum := verify(tmp, want, big)
	if !ok {
		os.Remove(tmp)
		return "", fmt.Errorf(i18n.T("deps.checksumMismatchGotExpectedFile"), a.Name, sum, want)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", err
	}
	return dst, nil
}

var httpClient = &http.Client{Timeout: 30 * time.Minute}

func download(a Artifact, dst string, progress Progress) error {
	req, err := http.NewRequest(http.MethodGet, a.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "VPNer")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	total := resp.ContentLength
	var done int64
	buf := make([]byte, 256<<10)
	last := time.Time{}
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, err := f.Write(buf[:n]); err != nil {
				return err
			}
			done += int64(n)
			if progress != nil && time.Since(last) > 200*time.Millisecond {
				progress(fmt.Sprintf(i18n.T("deps.downloading"), a.Name), done, total)
				last = time.Now()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
	}
	if progress != nil {
		progress(fmt.Sprintf(i18n.T("deps.downloading"), a.Name), done, total)
	}
	return f.Sync()
}

func verify(path, want string, useSHA512 bool) (bool, string) {
	f, err := os.Open(path)
	if err != nil {
		return false, ""
	}
	defer f.Close()
	h := sha256.New()
	if useSHA512 {
		h = sha512.New()
	}
	if _, err := io.Copy(h, f); err != nil {
		return false, ""
	}
	got := hex.EncodeToString(h.Sum(nil))
	return strings.EqualFold(got, want), got
}

// EnsureMihomo installs mihomo.exe into binDir and returns its path.
func EnsureMihomo(binDir, cacheDir string, progress Progress) (string, error) {
	a, err := Mihomo()
	if err != nil {
		return "", err
	}
	exe := filepath.Join(binDir, "mihomo.exe")
	marker := filepath.Join(binDir, "mihomo.version")
	if b, err := os.ReadFile(marker); err == nil && strings.TrimSpace(string(b)) == a.SHA256 {
		if _, err := os.Stat(exe); err == nil {
			return exe, nil
		}
	}
	zipPath, err := Fetch(a, cacheDir, progress)
	if err != nil {
		return "", err
	}
	if progress != nil {
		progress(fmt.Sprintf(i18n.T("deps.unpacking"), a.Name), 0, -1)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	var found bool
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", err
		}
		tmp := exe + ".new"
		out, err := os.Create(tmp)
		if err != nil {
			rc.Close()
			return "", err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return "", err
		}
		if err := os.Rename(tmp, exe); err != nil {
			return "", fmt.Errorf(i18n.T("deps.couldNotReplaceMihomoExe"), err)
		}
		found = true
		break
	}
	if !found {
		return "", errors.New(i18n.T("deps.mihomoArchiveHasNoExe"))
	}
	os.WriteFile(marker, []byte(a.SHA256), 0o644)
	return exe, nil
}
