package agent

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/reversewg"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

type wgBackend struct {
	core             *lifecycleCounter
	frozen           bool
	creates, removes int
	fail             bool
}

func (b *wgBackend) Preflight(context.Context, []reversewg.Ownership, []reversewg.Config) error {
	return nil
}
func (b *wgBackend) Healthy(context.Context, []reversewg.Config) bool { return true }
func (b *wgBackend) Firewall(_ context.Context, s string) error {
	b.frozen = strings.Contains(s, "ip saddr 10.10.0.6 drop")
	return nil
}
func (b *wgBackend) Create(context.Context, reversewg.Config) error {
	if b.core.running || !b.frozen {
		return errors.New("creation before freeze/stop")
	}
	b.creates++
	if b.fail {
		return errors.New("creation failed")
	}
	return nil
}
func (b *wgBackend) Remove(context.Context, reversewg.Ownership) error {
	if b.core.running || !b.frozen {
		return errors.New("removal before freeze/stop")
	}
	b.removes++
	return nil
}
func wgAgentRig(t *testing.T) (*Agent, *lifecycleCounter, *lostResponsePanel, *wgBackend) {
	t.Helper()
	a, c, p := checkpointRig(t)
	dir := t.TempDir()
	backend := &wgBackend{core: c}
	a.wireGuard = &wireGuardRuntime{ready: func() bool { return true }, transport: &reversewg.Manager{Dir: dir, Backend: backend}, shaping: &shaper.Shared{Dir: dir}}
	private, _, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	_, peer, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	a.node.WireGuardLinks = []spec.WireGuardLink{{Slot: 1, Exit: true, PrivateKey: private, PeerKey: peer, Endpoint: "192.0.2.10:51820", MTU: 1380}}
	return a, c, p, backend
}

func TestWireGuardAgentCheckpointsBeforeTransportChange(t *testing.T) {
	a, c, p, b := wgAgentRig(t)
	c.bytes = 1000
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.creates != 1 || !c.running {
		t.Fatal("transport or core not restored")
	}
	a.trafficJournal = nil
	a.report(context.Background())
	if p.total != 1000 {
		t.Fatalf("pre-change traffic lost or doubled: %d", p.total)
	}
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.creates != 1 {
		t.Fatal("healthy no-op recreated transport")
	}
	a.node.WireGuardLinks = nil
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.removes != 2 || a.wireGuardActive.Load() {
		t.Fatal("removed link left active resources")
	}
}

func TestWireGuardAgentFailureFreezesAndStopsEvenWithoutStats(t *testing.T) {
	a, c, _, b := wgAgentRig(t)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.statsErr = errors.New("stats unavailable")
	a.node.WireGuardLinks[0].MTU = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.apply(ctx); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	if c.running || !b.frozen || !a.dirty {
		t.Fatal("failed replacement left old sockets or forwarding alive")
	}
}

func TestWireGuardAgentShutdownRetiresExit(t *testing.T) {
	a, c, _, b := wgAgentRig(t)
	if err := a.apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.stopAll()
	if c.running || a.wireGuardActive.Load() || b.removes != 2 {
		t.Fatal("shutdown left transport active")
	}
}
