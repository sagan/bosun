package wgsetup

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"slices"
	"testing"
)

func fixture(missing ...string) machine {
	return machine{linux: true, root: true, distro: "debian", lookup: func(s string) (string, error) {
		if slices.Contains(missing, s) {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/" + s, nil
	}, system: func(s string) string {
		if slices.Contains(missing, s) {
			return ""
		}
		return "/usr/bin/" + s
	}, run: func(context.Context, string, ...string) error { panic("unexpected package operation") }}
}
func TestMissingPackages(t *testing.T) {
	for _, tc := range []struct {
		distro, manager string
		want            []string
	}{
		{"debian", "apt-get", []string{"iproute2", "wireguard-tools", "nftables", "procps"}},
		{"alpine", "apk", []string{"iproute2", "wireguard-tools", "nftables", "iproute2-tc", "procps"}},
		{"rocky", "dnf", []string{"iproute", "wireguard-tools", "nftables", "iproute-tc", "procps-ng"}},
	} {
		t.Run(tc.distro, func(t *testing.T) {
			m := fixture(tools...)
			m.distro = tc.distro
			s := m.inspect()
			if !s.Installable || s.Manager != tc.manager || !reflect.DeepEqual(s.Packages, tc.want) {
				t.Fatalf("%+v", s)
			}
		})
	}
}
func TestInstallOnlyMissing(t *testing.T) {
	m := fixture("wg")
	installed := false
	m.lookup = func(s string) (string, error) {
		if s == "wg" && !installed {
			return "", exec.ErrNotFound
		}
		return "/usr/bin/" + s, nil
	}
	var calls [][]string
	m.run = func(_ context.Context, name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if slices.Contains(args, "install") {
			installed = true
		}
		return nil
	}
	if got := m.install(context.Background()); got != "" {
		t.Fatal(got)
	}
	want := [][]string{{"apt-get", "-o", "DPkg::Lock::Timeout=30", "update"}, {"apt-get", "-o", "DPkg::Lock::Timeout=30", "install", "-y", "--no-install-recommends", "--no-upgrade", "wireguard-tools"}}
	if !reflect.DeepEqual(calls, want) {
		t.Fatal(calls)
	}
}
func TestNoUnsafeInstall(t *testing.T) {
	for _, kind := range []string{"container", "nonroot", "unknown", "path", "nonlinux"} {
		t.Run(kind, func(t *testing.T) {
			m := fixture("wg")
			switch kind {
			case "container":
				m.container = true
			case "nonroot":
				m.root = false
			case "unknown":
				m.distro = "unknown"
			case "path":
				m.system = fixture().system
			case "nonlinux":
				m.linux = false
			}
			if m.inspect().Installable {
				t.Fatal("unexpected installable")
			}
			if got := m.install(context.Background()); got != "unsupported" {
				t.Fatal(got)
			}
		})
	}
	if got := fixture().install(context.Background()); got != "" {
		t.Fatal(got)
	}
}
func TestInstallFailures(t *testing.T) {
	m := fixture("wg")
	m.run = func(context.Context, string, ...string) error { return errors.New("private repository detail") }
	if got := m.install(context.Background()); got != "install_failed" {
		t.Fatal(got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := m.install(ctx); got != "timeout" {
		t.Fatal(got)
	}
	m.run = func(context.Context, string, ...string) error { return nil }
	if got := m.install(context.Background()); got != "tools_missing" {
		t.Fatal(got)
	}
	installMu.Lock()
	got := m.install(context.Background())
	installMu.Unlock()
	if got != "busy" {
		t.Fatal(got)
	}
}
