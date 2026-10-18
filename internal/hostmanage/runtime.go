// Package hostmanage provides bounded observation and typed host mutations.
package hostmanage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/selfupdate"
)

type runner func(context.Context, string, ...string) (string, error)
type machine struct {
	root     string
	run      runner
	writable bool
}

func realMachine() *machine {
	return &machine{root: "/", run: command, writable: runtime.GOOS == "linux" && os.Geteuid() == 0 && !selfupdate.InContainer()}
}
func (m *machine) path(p string) string { return filepath.Join(m.root, strings.TrimPrefix(p, "/")) }
func (m *machine) read(p string) string {
	b, _ := readLimited(m.path(p))
	return strings.TrimSpace(string(b))
}
func readLimited(path string) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("not a regular file")
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 128<<10+1))
	if len(b) > 128<<10 {
		return nil, errors.New("file exceeds limit")
	}
	return b, e
}
func (m *machine) exists(p string) bool { _, e := os.Stat(m.path(p)); return e == nil }
func (m *machine) active(ctx context.Context, name string) bool {
	s, e := m.run(ctx, "systemctl", "is-active", name)
	return e == nil && strings.TrimSpace(s) == "active"
}

type output struct{ bytes.Buffer }

func (b *output) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 64<<10 {
		b.Buffer.Write(p[:min(n, (64<<10)-b.Len())])
	}
	return n, nil
}
func command(parent context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 8*time.Second)
	defer cancel()
	// Fixed executable directories avoid a service-supplied PATH selecting user code.
	var path string
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if s, e := os.Stat(p); e == nil && s.Mode().IsRegular() && s.Mode()&0111 != 0 {
			path = p
			break
		}
	}
	if path == "" {
		return "", errors.New("required tool is not installed")
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	cmd.WaitDelay = time.Second
	var out output
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}
func digest(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func kv(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) > 1 {
			if out[f[0]] != "" {
				out[f[0]] += ", "
			}
			out[f[0]] += strings.Join(f[1:], " ")
		}
	}
	return out
}
func props(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}
func (m *machine) supported(ctx context.Context) bool {
	return m.writable && m.exists("/run/systemd/system") && (strings.Contains(m.read("/etc/os-release"), "ID=debian") || strings.Contains(m.read("/etc/os-release"), "ID=ubuntu"))
}
