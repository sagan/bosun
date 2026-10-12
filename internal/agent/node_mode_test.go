package agent

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestMonitorModeRejectsProxyStateAndJobs(t *testing.T) {
	ctx := context.Background()
	a := New(&config.Config{NodeMode: spec.NodeMonitor, DataDir: t.TempDir()}, nopDriver{}, core.NewRegistry(), nil, slog.Default())
	a.users = []spec.User{}
	for _, n := range []*spec.Node{
		{Inbounds: []spec.Inbound{{Tag: "no", Protocol: spec.VLESS, Port: 443}}},
		{ReverseClients: []spec.ReverseClient{{ID: "no"}}},
		{Forwards: []spec.Forward{{Tag: "no", Port: 443, Target: "192.0.2.10:443"}}},
		{Overrides: map[string]json.RawMessage{"xray": []byte(`{}`)}},
		{Decoy: &spec.Decoy{Domain: "example.com"}},
	} {
		a.node = n
		if err := a.apply(ctx); !errors.Is(err, spec.ErrMonitorOnly) {
			t.Fatalf("accepted proxy state: %#v: %v", n, err)
		}
		if err := a.applyForwards(ctx); !errors.Is(err, spec.ErrMonitorOnly) {
			t.Fatalf("forward bypass: %v", err)
		}
	}
	a.node = &spec.Node{Mode: spec.NodeMonitor}
	if err := a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.ManageCore(ctx, spec.CoreRequest{}); !errors.Is(err, spec.ErrMonitorOnly) {
		t.Fatal(err)
	}
	for _, kind := range []string{spec.CoreManagementKind, "warp_register", "reality_scan"} {
		if res := a.execJob(ctx, agentproto.Job{ID: "job", Kind: kind}); res.Error != spec.ErrMonitorOnly.Error() {
			t.Fatal(res)
		}
	}
	rep := a.buildReport(nil, spec.SystemStatus{})
	if rep.NodeMode != spec.NodeMonitor || len(rep.Cores) != 0 {
		t.Fatal(rep)
	}
}

func TestNodeModeSwitchStopsCoresAndRejectsBusyOrFailedSwitch(t *testing.T) {
	ctx := context.Background()
	for _, fail := range []bool{false, true} {
		a, old, _, _ := coreChangeRig(t)
		a.node = &spec.Node{Mode: spec.NodeMonitor, ModeRevision: 1}
		a.users = nil
		called := 0
		a.ChangeMode = func(m spec.NodeMode, revision uint64, identity string) error {
			called++
			if old.Running() {
				t.Fatal("persist before stopping core")
			}
			if m != spec.NodeMonitor {
				t.Fatal(m)
			}
			if fail {
				return errors.New("disk failure")
			}
			return nil
		}
		a.jobsRunning["download"] = true
		if err := a.apply(ctx); err == nil || called != 0 || !old.Running() {
			t.Fatal("busy switch was allowed", err)
		}
		delete(a.jobsRunning, "download")
		err := a.apply(ctx)
		if (err != nil) != fail || called != 1 || old.Running() || a.modeChanging.Load() == fail {
			t.Fatal("invalid transition", err, called)
		}
	}
}

func TestMonitorToFullRequiresEmptyStateAndExplicitMode(t *testing.T) {
	a := New(&config.Config{NodeMode: spec.NodeMonitor, DataDir: t.TempDir()}, nopDriver{}, core.NewRegistry(), nil, slog.Default())
	called := false
	a.ChangeMode = func(m spec.NodeMode, revision uint64, identity string) error { called = true; return nil }
	a.node = &spec.Node{} // Older panels cannot silently enable proxy services.
	if err := a.apply(context.Background()); err != nil || called {
		t.Fatal(err, called)
	}
	a.node.Mode = spec.NodeFull
	a.node.ModeRevision = 1
	a.users = []spec.User{{Name: "secret"}}
	if err := a.apply(context.Background()); err == nil || called {
		t.Fatal(err, called)
	}
	a.users = nil
	if err := a.apply(context.Background()); err != nil || !called {
		t.Fatal(err, called)
	}
}

type modeIdentityDriver struct {
	nopDriver
	identity string
}

func (d modeIdentityDriver) TrafficIdentity() string { return d.identity }

func TestNodeModeRevisionRejectsStaleSideEffectsAndBindsToPanel(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{NodeMode: spec.NodeFull, NodeModeRevision: 4, NodeModeIdentity: "panel-one", DataDir: t.TempDir()}
	a := New(cfg, modeIdentityDriver{identity: "panel-one"}, core.NewRegistry(), nil, slog.Default())
	a.node = &spec.Node{Mode: spec.NodeFull, ModeRevision: 3}
	if err := a.apply(ctx); err == nil {
		t.Fatal("accepted stale mode state")
	}
	if err := a.applyForwards(ctx); err == nil || a.proxyModeReady(a.node) {
		t.Fatal("stale state allowed proxy side effects", err)
	}
	a.node.ModeRevision = 5
	if err := a.applyForwards(ctx); err == nil || a.proxyModeReady(a.node) {
		t.Fatal("unconfirmed revision allowed proxy side effects", err)
	}
	a.node.ModeRevision = 4
	if !a.proxyModeReady(a.node) || a.buildReport(nil, spec.SystemStatus{}).NodeModeRevision != 4 {
		t.Fatal("confirmed mode not ready")
	}
	// A new pairing identity must not inherit the previous panel's generation.
	a.driver = modeIdentityDriver{identity: "panel-two"}
	if a.modeRevision() != 0 || a.buildReport(nil, spec.SystemStatus{}).NodeModeRevision != 0 {
		t.Fatal("new panel inherited the old mode revision")
	}
	a.node = &spec.Node{Mode: spec.NodeMonitor, ModeRevision: 1}
	called := false
	a.ChangeMode = func(m spec.NodeMode, revision uint64, identity string) error {
		called = true
		if m != spec.NodeMonitor || revision != 1 || identity != "panel-two" {
			t.Fatal("wrong persisted mode identity")
		}
		return nil
	}
	if err := a.apply(ctx); err != nil || !called {
		t.Fatal("new panel cannot select mode", err)
	}
}
