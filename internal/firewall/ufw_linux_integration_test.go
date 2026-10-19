//go:build linux

package firewall

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run only inside a separately prepared mount+network namespace with private
// /etc/ufw and /etc/default/ufw. Never opt in on the host namespace.
func TestUFWIsolatedOwnership(t *testing.T) {
	if os.Getenv("BOSUN_FIREWALL_ISOLATED") != "1" {
		t.Skip("isolated UFW namespace only")
	}
	for _, kind := range []string{"mnt", "net"} {
		current, _ := os.Readlink("/proc/self/ns/" + kind)
		host, _ := os.Readlink("/proc/1/ns/" + kind)
		if current == host || current == "" || host == "" {
			t.Fatal("requires isolated " + kind + " namespace")
		}
	}
	ctx := context.Background()
	m := &Manager{StateFile: filepath.Join(t.TempDir(), "firewall.json")}
	run := func(args ...string) string {
		t.Helper()
		b, e := exec.Command("ufw", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("ufw %v failed: %s", args, b)
		}
		return string(b)
	}
	run("--force", "reset")
	run("--force", "enable")
	run("allow", "18443/tcp", "comment", "operator-rule")
	ports := []Port{{Proto: "tcp", Port: 18443, Source: "inbound:manual"}, {Proto: "tcp", Port: 18444, Source: "inbound:a"}, {Proto: "udp", Port: 18444, Source: "forward:b"}}
	if e := m.Apply(ctx, ports); e != nil {
		t.Fatal(e)
	}
	if m.Status().Opened != 2 {
		t.Fatalf("%+v", m.Status())
	}
	// Add an independent operator allowance while the managed rule exists.
	run("allow", "from", "192.0.2.0/24", "to", "any", "port", "18444", "proto", "tcp", "comment", "operator-later")
	if e := m.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	s := run("show", "added")
	if !strings.Contains(s, "operator-rule") || !strings.Contains(s, "operator-later") || strings.Contains(s, "18444/udp") {
		t.Fatal("manual retention or protocol isolation failed")
	}
	// Remove only the operator's narrow rule, then reconcile owned residue.
	run("delete", "allow", "from", "192.0.2.0/24", "to", "any", "port", "18444", "proto", "tcp")
	restarted := &Manager{StateFile: m.StateFile}
	if e := restarted.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	s = run("show", "added")
	if !strings.Contains(s, "operator-rule") || strings.Contains(s, "bosun-auto-") {
		t.Fatal("restart ownership cleanup failed")
	}
}
