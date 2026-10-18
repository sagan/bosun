package netdiag

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Upstream GPL-3.0 executable is downloaded separately, never linked or copied
// into bosun. Fixed release and GitHub asset digests reviewed 2026-10-18.
const nextTraceVersion = "v1.7.4"

var nextTraceHashes = map[string]string{
	"amd64": "68b6a2210724a4b9439d9337ac69bf17fc7d662002a9a9dbdc5b96c1ab44ca26",
	"arm64": "ce8fb581c2bd30a157aec4a38e5c0fa1c79eac3b761a978146267b6ae1c678e3",
}

func routeToolPath(root string, create bool) (string, error) {
	if root == "" || !filepath.IsAbs(root) {
		return "", os.ErrInvalid
	}
	// Refuse writable/symlink tool directories before running downloaded code.
	dir := root
	for _, part := range []string{"", "tools", "nexttrace", nextTraceVersion} {
		dir = filepath.Join(dir, part)
		if create && part != "" {
			if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
				return "", err
			}
		}
		st, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode()&0022 != 0 || !ok || int(owner.Uid) != os.Geteuid() {
			return "", os.ErrPermission
		}
	}
	return filepath.Join(dir, "nexttrace-tiny"), nil
}
func verifyRouteTool(path, digest string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode()&0022 != 0 || st.Mode()&0100 == 0 || !ok || int(owner.Uid) != os.Geteuid() {
		return os.ErrPermission
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if err != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("tool checksum mismatch")
	}
	return nil
}
func installRouteTool(ctx context.Context, root string) error {
	path, err := routeToolPath(root, true)
	if err != nil {
		return err
	}
	digest := nextTraceHashes[runtime.GOARCH]
	if verifyRouteTool(path, digest) == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://github.com/nxtrace/NTrace-core/releases/download/"+nextTraceVersion+"/nexttrace-tiny_linux_"+runtime.GOARCH, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 70 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || r.URL.Scheme != "https" || (r.URL.Hostname() != "github.com" && r.URL.Hostname() != "release-assets.githubusercontent.com" && r.URL.Hostname() != "objects.githubusercontent.com") {
			return errors.New("unexpected tool redirect")
		}
		return nil
	}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("tool download failed")
	}
	return saveRouteTool(path, digest, resp.Body)
}
func saveRouteTool(path, digest string, body io.Reader) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".nexttrace-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, (64<<20)+1))
	if err != nil || n > 64<<20 || hex.EncodeToString(h.Sum(nil)) != digest {
		return errors.New("tool checksum mismatch")
	}
	if err = f.Chmod(0700); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func rawICMP(network, addr string) string {
	c, err := net.ListenPacket(network, addr)
	if err == nil {
		c.Close()
		return "ready"
	}
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		return "permission"
	}
	return "unavailable"
}
func runRouteTool(ctx context.Context, root string, install bool) (*spec.RouteToolStatus, string) {
	s := &spec.RouteToolStatus{State: "missing", IPv4: "unavailable", IPv6: "unavailable", Installable: runtime.GOOS == "linux" && nextTraceHashes[runtime.GOARCH] != "" && filepath.IsAbs(root)}
	if runtime.GOOS != "linux" {
		s.State = "unsupported"
		return s, "unavailable"
	}
	if install {
		if !s.Installable {
			s.State = "unsupported"
			return s, "unavailable"
		}
		if err := installRouteTool(ctx, root); err != nil {
			s.State = "install_failed"
			return s, "install_failed"
		}
	}
	path, err := routeToolPath(root, false)
	if err == nil {
		err = verifyRouteTool(path, nextTraceHashes[runtime.GOARCH])
		if err == nil {
			s.Engine = "nexttrace"
			s.Version = nextTraceVersion
			s.Managed = true
		}
	}
	if err != nil && !os.IsNotExist(err) && root != "" {
		s.State = "invalid"
		return s, "unavailable"
	}
	if s.Engine == "" {
		path, err = exec.LookPath("traceroute")
		if err != nil {
			return s, "unavailable"
		}
		s.Engine = "traceroute"
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	args := []string{"--version"}
	cmd := exec.CommandContext(cctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	b := &boundedOutput{}
	cmd.Stdout = b
	cmd.Stderr = b
	if cmd.Run() != nil || b.truncated || (!s.Managed && !strings.Contains(b.text(), "Modern traceroute")) {
		s.State = "incompatible"
		return s, "unavailable"
	}
	if !s.Managed {
		fields := strings.Fields(b.text())
		for i, v := range fields {
			if v == "version" && i+1 < len(fields) {
				s.Version = fields[i+1]
				break
			}
		}
	}
	s.IPv4 = rawICMP("ip4:icmp", "0.0.0.0")
	s.IPv6 = rawICMP("ip6:ipv6-icmp", "::")
	s.State = "ready"
	if s.IPv4 != "ready" && s.IPv6 != "ready" {
		s.State = "unavailable"
		if s.IPv4 == "permission" || s.IPv6 == "permission" {
			s.State = "permission"
		}
		return s, "unavailable"
	}
	return s, "ok"
}
