// Package wgsetup checks and installs a fixed set of reverse-WG system tools.
package wgsetup

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

var tools = []string{"ip", "wg", "nft", "tc", "sysctl"}
var installMu sync.Mutex

type machine struct {
	linux, root, container bool
	distro                 string
	lookup                 func(string) (string, error)
	system                 func(string) string
	run                    func(context.Context, string, ...string) error
}

func systemTool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0111 != 0 {
			return p
		}
	}
	return ""
}
func current() machine {
	raw, _ := os.ReadFile("/etc/os-release")
	id := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"'")
		}
	}
	return machine{linux: runtime.GOOS == "linux", root: os.Geteuid() == 0, container: selfupdate.InContainer(), distro: id, lookup: exec.LookPath, system: systemTool, run: runCommand}
}
func (m machine) plan() (string, map[string]string) {
	switch m.distro {
	case "debian", "ubuntu":
		return "apt-get", map[string]string{"ip": "iproute2", "tc": "iproute2", "wg": "wireguard-tools", "nft": "nftables", "sysctl": "procps"}
	case "alpine":
		return "apk", map[string]string{"ip": "iproute2", "tc": "iproute2-tc", "wg": "wireguard-tools", "nft": "nftables", "sysctl": "procps"}
	case "fedora", "rhel", "centos", "rocky", "almalinux":
		return "dnf", map[string]string{"ip": "iproute", "tc": "iproute-tc", "wg": "wireguard-tools", "nft": "nftables", "sysctl": "procps-ng"}
	}
	return "", nil
}
func (m machine) inspect() *spec.WireGuardSetup {
	manager, packages := m.plan()
	s := &spec.WireGuardSetup{CheckedAt: time.Now().Unix(), Checks: []spec.PrivateAccessCheck{}, Packages: []string{}, Manager: manager}
	s.Checks = append(s.Checks, spec.PrivateAccessCheck{ID: "root", OK: m.root})
	pathOK := true
	for _, tool := range tools {
		_, err := m.lookup(tool)
		s.Checks = append(s.Checks, spec.PrivateAccessCheck{ID: "tool_" + tool, OK: err == nil})
		if err != nil {
			if m.system(tool) != "" {
				pathOK = false
			} else if pkg := packages[tool]; pkg != "" && !slices.Contains(s.Packages, pkg) {
				s.Packages = append(s.Packages, pkg)
			}
		}
	}
	s.Checks = append(s.Checks, spec.PrivateAccessCheck{ID: "tool_path", OK: pathOK})
	s.Installable = m.linux && m.root && !m.container && manager != "" && m.system(manager) != "" && len(s.Packages) > 0
	return s
}
func Inspect() *spec.WireGuardSetup      { return current().inspect() }
func Install(ctx context.Context) string { return current().install(ctx) }
func (m machine) install(ctx context.Context) string {
	if !installMu.TryLock() {
		return "busy"
	}
	defer installMu.Unlock()
	s := m.inspect()
	if len(s.Packages) == 0 {
		for _, c := range s.Checks {
			if !c.OK {
				return "unsupported"
			}
		}
		return ""
	}
	if !s.Installable {
		return "unsupported"
	}
	if ctx.Err() != nil {
		return "timeout"
	}
	var err error
	switch s.Manager {
	case "apt-get":
		err = m.run(ctx, s.Manager, "-o", "DPkg::Lock::Timeout=30", "update")
		if err == nil {
			err = m.run(ctx, s.Manager, append([]string{"-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "--no-upgrade"}, s.Packages...)...)
		}
	case "apk":
		err = m.run(ctx, s.Manager, append([]string{"add", "--no-cache"}, s.Packages...)...)
	case "dnf":
		err = m.run(ctx, s.Manager, append([]string{"install", "-y", "--setopt=timeout=30", "--setopt=retries=1"}, s.Packages...)...)
	}
	if ctx.Err() != nil {
		return "timeout"
	}
	if err != nil {
		return "install_failed"
	}
	for _, c := range m.inspect().Checks {
		if strings.HasPrefix(c.ID, "tool_") && !c.OK {
			return "tools_missing"
		}
	}
	return ""
}
