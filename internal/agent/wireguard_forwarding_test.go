package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/wgfirewall"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type forwardingFixture struct {
	backend         *wgBackend
	fail            bool
	cleanupFail     bool
	opened, cleaned int
	status          wgfirewall.Status
}

func (f *forwardingFixture) Apply(_ context.Context, links []spec.WireGuardLink) error {
	f.status = wgfirewall.Status{State: "synced", Backend: "ufw", CheckedAt: time.Now().Unix()}
	if len(links) == 0 {
		f.cleaned++
		if f.cleanupFail {
			f.status.State, f.status.Reason = "error", "ufw_forward_rule_conflict"
			return errors.New(f.status.Reason)
		}
		return nil
	}
	if f.backend.frozen {
		return errors.New("host allowance before transport ACL")
	}
	for _, link := range links {
		if !link.Exit || !link.AutoForwarding {
			return errors.New("manual or transit link adopted")
		}
	}
	f.opened++
	if f.fail {
		f.status.State, f.status.Reason = "error", "ufw_forward_rule_update_failed"
		return errors.New(f.status.Reason)
	}
	return nil
}

func TestWireGuardHostCleanupFailureKeepsControlPlaneRecoverable(t *testing.T) {
	a, core, _, backend := wgAgentRig(t)
	f := &forwardingFixture{backend: backend}
	a.wireGuard.forwarding = f
	a.node.WireGuardLinks[0].AutoForwarding = true
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.cleanupFail = true
	err := a.clearWireGuard(context.Background())
	var hostOnly *wireGuardForwardingCleanupError
	if !errors.As(err, &hostOnly) || core.running || a.wireGuardActive.Load() {
		t.Fatalf("host-only failure must retain diagnostics after retiring transport: %v", err)
	}
	if rep := a.wireGuardReport(context.Background()); rep.Forwarding == nil || rep.Forwarding.State != "error" {
		t.Fatalf("cleanup diagnostic unavailable: %+v", rep)
	}
	// Opting out cannot hide or bypass a conflicting ownership journal.
	a.node.WireGuardLinks[0].AutoForwarding = false
	if err := a.apply(context.Background()); err == nil || core.running || !a.dirty {
		t.Fatalf("unresolved cleanup started proxy: %v", err)
	}
	f.cleanupFail = false
	if err := a.apply(context.Background()); err != nil || !core.running {
		t.Fatalf("resolved conflict failed to recover: %v", err)
	}
}
func (f *forwardingFixture) Status() wgfirewall.Status { return f.status }

func TestWireGuardAutomaticForwardingLifecycle(t *testing.T) {
	a, core, _, backend := wgAgentRig(t)
	f := &forwardingFixture{backend: backend}
	a.wireGuard.forwarding = f
	// Existing connections are not adopted on upgrade.
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.opened != 0 || a.wireGuard.forwardingStatus.State != "manual" {
		t.Fatal("legacy forwarding was adopted")
	}
	a.node.WireGuardLinks[0].AutoForwarding = true
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.opened != 1 || !core.running || a.wireGuard.forwardingStatus.State != "synced" {
		t.Fatal("automatic forwarding not applied")
	}
	f.fail = true
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("failed host allowance accepted")
	}
	if core.running || !backend.frozen || !a.dirty || f.cleaned < 2 {
		t.Fatal("host forwarding failure did not freeze and retire rules")
	}
	rep := a.wireGuardReport(context.Background())
	if rep.Applied || rep.Forwarding == nil || rep.Forwarding.State != "error" || rep.Forwarding.Reason != "ufw_forward_rule_update_failed" {
		t.Fatalf("failure lost during cleanup: %+v", rep)
	}
	f.fail = false
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !core.running || a.wireGuard.forwardingStatus.State != "synced" {
		t.Fatal("retry did not restore the desired forwarding")
	}
	a.node.WireGuardLinks[0].AutoForwarding = false
	before := f.cleaned
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.cleaned <= before || a.wireGuard.forwardingStatus.State != "manual" {
		t.Fatal("opting out retained automatic allowances")
	}
	a.node.WireGuardLinks[0].AutoForwarding = true
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	before = f.cleaned
	a.stopAll()
	if core.running || f.cleaned <= before {
		t.Fatal("shutdown left host allowances")
	}
}

func TestWireGuardAutomaticForwardingRespectsGlobalSwitch(t *testing.T) {
	a, core, _, backend := wgAgentRig(t)
	f := &forwardingFixture{backend: backend}
	a.wireGuard.forwarding = f
	a.node.WireGuardLinks[0].AutoForwarding = true
	off := false
	a.cfg.FirewallAutoOpen = &off
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("global opt-out ignored")
	}
	if f.opened != 0 || core.running || !backend.frozen {
		t.Fatal("opt-out left automatic forwarding active")
	}
	if a.wireGuard.forwardingStatus.Reason != "automatic_forwarding_disabled" {
		t.Fatal("missing global switch diagnostic")
	}
}
