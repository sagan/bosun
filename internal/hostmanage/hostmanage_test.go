package hostmanage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func fixture(t *testing.T) (*manager, *[]string) {
	t.Helper()
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"etc/systemd/system", "etc/ssh", "etc/apt/apt.conf.d", "etc/sysctl.d", "run/systemd/system", "var/lib/bosun/host-management"} {
		if e = os.MkdirAll(filepath.Join(root, p), 0700); e != nil {
			t.Fatal(e)
		}
	}
	write := func(p, s string) {
		if e := os.WriteFile(filepath.Join(root, p), []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("etc/os-release", "ID=debian\n")
	write("etc/hostname", "original\n")
	write("etc/ssh/sshd_config", "Port 22\nPasswordAuthentication yes\n")
	write("etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	calls := []string{}
	hostname := "original"
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		s := name + " " + strings.Join(args, " ")
		calls = append(calls, s)
		switch name {
		case "hostname":
			if len(args) > 0 {
				hostname = args[0]
			}
			return hostname, nil
		case "sshd":
			return "port 22\npermitrootlogin no\npasswordauthentication no\npubkeyauthentication yes\nauthorizedkeysfile .ssh/authorized_keys\n", nil
		case "systemctl":
			if len(args) > 0 && args[0] == "is-active" {
				if args[1] == "bosun-host-recovery.timer" || args[1] == "ssh.service" {
					return "active", nil
				}
				return "inactive", errors.New("inactive")
			}
			return "", nil
		case "ss":
			return "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*", nil
		case "timedatectl":
			return "Timezone=UTC\nNTP=no\nNTPSynchronized=no", nil
		}
		return "", errors.New("unavailable")
	}
	return &manager{dir: filepath.Join(root, "var/lib/bosun/host-management"), m: &machine{root: root, run: run, writable: true}}, &calls
}
func TestHostHostnameApplyAndStalePlan(t *testing.T) {
	g, calls := fixture(t)
	ctx := context.Background()
	s := g.snapshot(ctx)
	r := spec.HostRequest{Action: "apply", Section: "hostname", Revision: s.Revision, Values: map[string]string{"hostname": "new-host"}}
	got := g.execute(ctx, "panel", digest("job"), r)
	if got.Outcome != "complete" {
		t.Fatal(got)
	}
	if g.m.read("/etc/hostname") != "new-host" {
		t.Fatal("not persisted")
	}
	if g.pending() != nil {
		t.Fatal("completed operation is pending")
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "systemctl enable --now bosun-host-recovery.timer") {
		t.Fatal("no independent recovery")
	}
	got = g.execute(ctx, "panel", digest("other"), r)
	if got.Outcome != "failed" || !strings.Contains(got.Message, "changed") {
		t.Fatal("accepted stale plan", got)
	}
}
func TestHostRecoveryRestoresAbsentAndExistingFiles(t *testing.T) {
	g, _ := fixture(t)
	ctx := context.Background()
	tx := &transaction{ID: digest("job"), Section: "hostname", Phase: "waiting", Deadline: time.Now().Add(-time.Minute).Unix(), Files: []fileChange{{Path: "/etc/hostname", After: []byte("new\n")}, {Path: "/etc/new-config", After: []byte("new")}}}
	if e := g.capture(tx); e != nil {
		t.Fatal(e)
	}
	if e := g.writeFiles(tx, false); e != nil {
		t.Fatal(e)
	}
	if e := g.save("pending.json", tx); e != nil {
		t.Fatal(e)
	}
	if e := g.restore(ctx, tx); e != nil {
		t.Fatal(e)
	}
	if g.m.read("/etc/hostname") != "original" {
		t.Fatal("old value lost")
	}
	if g.m.exists("/etc/new-config") {
		t.Fatal("new file retained")
	}
	if g.pending() != nil {
		t.Fatal("recovery still pending")
	}
}
func TestHostRecoveryFailureAndCorruptJournalStayPending(t *testing.T) {
	g, _ := fixture(t)
	ctx := context.Background()
	tx := &transaction{ID: digest("job"), Phase: "waiting", Undo: []invocation{cmd("missing-tool")}}
	if e := g.restore(ctx, tx); e == nil {
		t.Fatal("ignored restore failure")
	}
	if p := g.pending(); p == nil || p.Phase != "recovery_failed" {
		t.Fatal(p)
	}
	if e := atomic(filepath.Join(g.dir, "pending.json"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if p := g.pending(); p == nil || p.Phase != "journal_invalid" {
		t.Fatal("corruption treated as no pending transaction", p)
	}
	r := spec.HostRequest{Action: "apply", Section: "hostname", Revision: g.snapshot(ctx).Revision, Values: map[string]string{"hostname": "new"}}
	if v := g.execute(ctx, "panel", digest("new"), r); v.Outcome != "failed" {
		t.Fatal(v)
	}
}
func TestHostConfirmationIdentityAndDeadline(t *testing.T) {
	g, _ := fixture(t)
	tx := &transaction{ID: digest("job"), Identity: digest("panel"), Section: "firewall", Phase: "waiting", Deadline: time.Now().Add(time.Minute).Unix()}
	if e := g.save("pending.json", tx); e != nil {
		t.Fatal(e)
	}
	r := spec.HostRequest{Action: "confirm", Transaction: tx.ID, Verified: true}
	if v := g.execute(context.Background(), "other", digest("x"), r); v.Outcome != "failed" {
		t.Fatal("foreign panel confirmed", v)
	}
	tx.Deadline = 1
	_ = g.save("pending.json", tx)
	if v := g.execute(context.Background(), "panel", digest("x"), r); v.Outcome != "failed" {
		t.Fatal("late confirmation", v)
	}
	r.Action = "rollback"
	if v := g.execute(context.Background(), "panel", digest("x"), r); v.Outcome != "restored" {
		t.Fatal(v)
	}
}
func TestHostRefusesSymlinkWrites(t *testing.T) {
	g, _ := fixture(t)
	target := g.m.path("/etc/target")
	if e := os.WriteFile(target, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	path := g.m.path("/etc/link")
	if e := os.Symlink(target, path); e != nil {
		t.Fatal(e)
	}
	if e := g.capture(&transaction{Files: []fileChange{{Path: "/etc/link"}}}); e == nil {
		t.Fatal("captured symlink")
	}
	if e := atomic(path, []byte("bad"), 0600); e == nil {
		t.Fatal("replaced symlink")
	}
	if g.m.read("/etc/target") != "preserve" {
		t.Fatal("target changed")
	}
}
func TestHostSSHPortIsAuthoritativeAndRepeatable(t *testing.T) {
	original := "# original\nPort 22\nPort 2222\nPasswordAuthentication yes\n"
	settings := map[string]string{"Port": "22\n2022", "PasswordAuthentication": "no"}
	one := sshConfig(original, settings)
	if strings.Contains(one, "Port 2222") {
		t.Fatal(one)
	}
	settings["Port"] = "2022"
	two := sshConfig(one, settings)
	if strings.Count(two, "Port ") != 1 || strings.Contains(two, "Port 22\n") {
		t.Fatal(two)
	}
	if !strings.Contains(two, "PasswordAuthentication yes") {
		t.Fatal("unmanaged content discarded")
	}
}
func TestHostUnsafeRequestsNeverBecomeCommands(t *testing.T) {
	g, calls := fixture(t)
	for _, r := range []spec.HostRequest{
		{Section: "hostname", Values: map[string]string{"hostname": "--help"}}, {Section: "port", Values: map[string]string{"port": "22;id"}}, {Section: "admin", Values: map[string]string{"user": "root", "public_key": "bad"}}, {Section: "dns", Values: map[string]string{"servers": "--help"}}, {Section: "time", Values: map[string]string{"timezone": "../../etc/passwd", "ntp": "true"}},
	} {
		if _, e := g.plan(context.Background(), r); e == nil {
			t.Fatal("accepted", r)
		}
	}
	for _, s := range *calls {
		if strings.Contains(s, "--help") || strings.Contains(s, "22;id") {
			t.Fatal("unsafe command", s)
		}
	}
}

func TestHostRecoveryPreservesExternalEdits(t *testing.T) {
	g, _ := fixture(t)
	tx := &transaction{ID: digest("job"), Phase: "waiting", Files: []fileChange{{Path: "/etc/hostname", After: []byte("new\n")}}}
	if e := g.capture(tx); e != nil {
		t.Fatal(e)
	}
	if e := g.writeFiles(tx, false); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(g.m.path("/etc/hostname"), []byte("external\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := g.restore(context.Background(), tx); e == nil {
		t.Fatal("overwrote unrelated edit")
	}
	if g.m.read("/etc/hostname") != "external" {
		t.Fatal("lost external edit")
	}
}
func TestHostRecoveryAcceptsIntermediateSSHState(t *testing.T) {
	g, _ := fixture(t)
	tx := &transaction{ID: digest("job"), Phase: "waiting", Files: []fileChange{{Path: "/etc/hostname", After: []byte("final\n"), Interim: []byte("intermediate\n")}}}
	if e := g.capture(tx); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(g.m.path("/etc/hostname"), []byte("intermediate\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := g.restore(context.Background(), tx); e != nil {
		t.Fatal(e)
	}
	if g.m.read("/etc/hostname") != "original" {
		t.Fatal("intermediate recovery failed")
	}
}

func TestHostReceiptsPreventReplayAndCorruption(t *testing.T) {
	g, calls := fixture(t)
	ctx := context.Background()
	r := spec.HostRequest{Action: "apply", Section: "hostname", Revision: g.snapshot(ctx).Revision, Values: map[string]string{"hostname": "new-host"}}
	one := g.perform(ctx, "panel", "job", r)
	if one.Outcome != "complete" {
		t.Fatal(one)
	}
	before := len(*calls)
	two := g.perform(ctx, "panel", "job", r)
	if two.Outcome != "complete" || len(*calls) != before {
		t.Fatal("replayed operation", two)
	}
	r.Values["hostname"] = "different"
	if got := g.perform(ctx, "panel", "job", r); got.Outcome != "invalid" {
		t.Fatal("accepted reused id with different request", got)
	}
	path := filepath.Join(g.dir, "receipt-"+digest("panel\x00job")+".json")
	if e := atomic(path, []byte("corrupt"), 0600); e != nil {
		t.Fatal(e)
	}
	if got := g.perform(ctx, "panel", "job", r); got.Outcome != "unknown" {
		t.Fatal("replayed unreadable receipt", got)
	}
	if g.m.read("/etc/hostname") != "new-host" {
		t.Fatal("unexpected mutation")
	}
}
