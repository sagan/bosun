package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type lifecycleCounter struct {
	fakeCore
	bytes    int64
	tagBytes int64
	statsErr error
	onReset  func()
}

func (c *lifecycleCounter) Stats(_ context.Context, reset bool) (map[string]spec.Traffic, error) {
	if c.statsErr != nil {
		return nil, c.statsErr
	}
	n := c.bytes
	if reset {
		c.tagBytes += n
		c.bytes = 0
		if c.onReset != nil {
			c.onReset()
		}
	}
	return map[string]spec.Traffic{"customer|ssh": {Up: n}, "customer|native": {Down: n}}, nil
}
func (c *lifecycleCounter) InboundStats(_ context.Context, reset bool) (map[string]spec.Traffic, error) {
	n := c.tagBytes
	if reset {
		c.tagBytes = 0
	}
	return map[string]spec.Traffic{"ssh": {Up: n}, "native": {Down: n}}, nil
}
func (c *lifecycleCounter) Apply(context.Context, *core.Bundle) error {
	if c.fail != nil {
		return c.fail
	}
	c.bytes = 0
	return nil
}
func (c *lifecycleCounter) Stop(context.Context) error { c.running = false; c.bytes = 0; return nil }
func checkpointRig(t *testing.T) (*Agent, *lifecycleCounter, *lostResponsePanel) {
	t.Helper()
	c := &lifecycleCounter{fakeCore: fakeCore{name: "singbox-extended", protos: []spec.Protocol{spec.VLESS}, running: true}}
	p := &lostResponsePanel{seen: map[uint64]bool{}}
	reg := core.NewRegistry()
	reg.Register(c)
	a := New(&config.Config{DataDir: t.TempDir()}, p, reg, nil, slog.Default())
	a.node = &spec.Node{Inbounds: []spec.Inbound{{Tag: "ssh", Protocol: spec.VLESS, Port: 443}}}
	a.users = []spec.User{{ID: 1, Name: "customer"}}
	a.rebuildUserIndex()
	a.rememberCoreUsers(c.Name(), a.node.Inbounds)
	return a, c, p
}
func TestTrafficCheckpointReloadDisableAndShutdown(t *testing.T) {
	for _, mode := range []string{"reload", "disable", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			a, c, p := checkpointRig(t)
			c.bytes = 1000
			switch mode {
			case "disable":
				a.node.Inbounds = nil
				fallthrough
			case "reload":
				if err := a.apply(context.Background()); err != nil {
					t.Fatal(err)
				}
			case "shutdown":
				a.stopAll()
			}
			if p.total != 0 {
				t.Fatal("checkpoint unexpectedly required panel delivery")
			}
			// Only the durable file survives; no report happened before the action.
			a.trafficJournal = nil
			a.report(context.Background())
			if p.total != 1000 {
				t.Fatalf("lost pre-%s traffic: %d", mode, p.total)
			}
			r := p.reports[0]
			if r.Inbounds["ssh"].Up != 1000 {
				t.Fatal("SSH aggregate missing/doubled", r.Inbounds)
			}
			if r.Inbounds["native"].Down != 1000 {
				t.Fatal("native inbound stats lost")
			}
		})
	}
}
func TestCheckpointBehindUnacknowledgedBatchSurvivesRestart(t *testing.T) {
	a, c, p := checkpointRig(t)
	c.bytes = 1000
	p.lose = true
	a.report(context.Background())
	frozen := p.reports[0]
	c.bytes = 700
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p.total != 1000 || a.trafficJournal.Pending.Seq != frozen.TrafficSeq {
		t.Fatal("checkpoint changed in-flight batch")
	}
	c.bytes = 300
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.trafficJournal = nil
	a.report(context.Background())
	retry := p.reports[1]
	if !reflect.DeepEqual(retry.Traffic, frozen.Traffic) || !reflect.DeepEqual(retry.Inbounds, frozen.Inbounds) {
		t.Fatal("retry changed immutable report")
	}
	a.report(context.Background())
	if p.total != 2000 {
		t.Fatal("buffered traffic lost or charged twice", p.total)
	}
	if p.reports[2].TrafficSeq != frozen.TrafficSeq+1 || p.reports[2].Inbounds["ssh"].Up != 1000 {
		t.Fatal("bad next batch", p.reports[2].Traffic)
	}
}
func TestCheckpointUsesRunningIdentitiesAfterDesiredUsersChange(t *testing.T) {
	a, c, p := checkpointRig(t)
	c.bytes = 1000
	a.users = []spec.User{{ID: 2, Name: "customer"}}
	a.rebuildUserIndex()
	c.fail = errors.New("invalid next configuration")
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("expected apply failure")
	}
	c.bytes = 500
	a.report(context.Background())
	for _, sample := range p.reports[0].Traffic {
		if sample.UserID != 1 {
			t.Fatal("old core billed new identity", sample)
		}
	}
	if p.total != 1500 {
		t.Fatal(p.total)
	}
	c.fail = nil
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.bytes = 300
	a.report(context.Background())
	for _, sample := range p.reports[1].Traffic {
		if sample.Up > 0 && sample.UserID != 2 {
			t.Fatal("new core billed old identity", sample)
		}
	}
}
func TestCheckpointSaveFailureKeepsCoreAndCounters(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 1000
	if err := a.loadTrafficJournal(); err != nil {
		t.Fatal(err)
	}
	path := a.trafficJournal.path
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := a.apply(context.Background()); err == nil {
		t.Fatal("expected save failure")
	}
	if !c.running || c.bytes != 1000 {
		t.Fatal("discarded unsaved counters")
	}
	// Revocation is fail-closed even when accounting cannot be saved.
	a.privatePolicyActive = true
	if err := a.apply(context.Background()); err == nil || c.running {
		t.Fatal("accounting failure kept revoked sockets alive")
	}
}
func TestCheckpointReadFailureDoesNotRestart(t *testing.T) {
	a, c, _ := checkpointRig(t)
	c.bytes = 1000
	c.statsErr = errors.New("stats unavailable")
	if err := a.apply(context.Background()); err == nil || !c.running || c.bytes != 1000 {
		t.Fatal("restarted without readable counters")
	}
}

func TestCheckpointFailedSaveAfterResetIsRetried(t *testing.T) {
	a, c, p := checkpointRig(t)
	if err := a.loadTrafficJournal(); err != nil {
		t.Fatal(err)
	}
	path := a.trafficJournal.path
	c.bytes = 1000
	c.onReset = func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.apply(context.Background()); err == nil || !c.running || c.bytes != 0 {
		t.Fatal("expected failed save after collecting counters, with core kept running")
	}
	c.onReset = nil
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.bytes = 600
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.trafficJournal = nil
	a.report(context.Background())
	if p.total != 1600 || p.reports[0].Inbounds["ssh"].Up != 1600 {
		t.Fatal("failed save retry lost or doubled counters", p.total, p.reports[0].Inbounds)
	}
}
