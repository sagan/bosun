package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type countingCore struct {
	fakeCore
	pending int64
}

func (c *countingCore) Stats(_ context.Context, reset bool) (map[string]spec.Traffic, error) {
	n := c.pending
	if reset {
		c.pending = 0
	}
	return map[string]spec.Traffic{"customer": {Up: n}}, nil
}

type lostResponsePanel struct {
	nopDriver
	seen    map[uint64]bool
	total   int64
	lose    bool
	reports []agentproto.Report
}

func (p *lostResponsePanel) Report(_ context.Context, r agentproto.Report) (bool, error) {
	p.reports = append(p.reports, r)
	if !p.seen[r.TrafficSeq] {
		for _, t := range r.Traffic {
			p.total += t.Up
		}
		p.seen[r.TrafficSeq] = true
	}
	if p.lose {
		p.lose = false
		return false, errors.New("response lost after commit")
	}
	return false, nil
}
func reportingAgent(t *testing.T, dir string, p *lostResponsePanel, c *countingCore) *Agent {
	t.Helper()
	reg := core.NewRegistry()
	reg.Register(c)
	a := New(&config.Config{DataDir: dir}, p, reg, nil, slog.Default())
	a.userIDs = map[string]int64{"customer": 1}
	return a
}
func TestLostTrafficResponseKeepsBatchImmutable(t *testing.T) {
	c := &countingCore{fakeCore: fakeCore{name: "test", running: true}, pending: 1000}
	p := &lostResponsePanel{seen: map[uint64]bool{}, lose: true}
	a := reportingAgent(t, t.TempDir(), p, c)
	a.report(context.Background())
	c.pending = 700
	a.report(context.Background())
	a.report(context.Background())
	if p.total != 1700 {
		t.Fatalf("new bytes lost after retry: %d", p.total)
	}
	if len(p.reports[1].Traffic) != 1 || p.reports[1].Traffic[0].Up != 1000 {
		t.Fatal("retry changed frozen batch", p.reports[1].Traffic)
	}
}

func TestTrafficJournalSurvivesRestartAndRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	c := &countingCore{fakeCore: fakeCore{name: "test", running: true}, pending: 1000}
	p := &lostResponsePanel{seen: map[uint64]bool{}, lose: true}
	a := reportingAgent(t, dir, p, c)
	a.report(context.Background())
	epoch, seq := a.trafficJournal.Epoch, a.trafficJournal.Pending.Seq
	// Recreate the process with no in-memory state. A response had been lost,
	// so the disk batch must be delivered unchanged and then acknowledged.
	c.pending = 700
	b := reportingAgent(t, dir, p, c)
	b.report(context.Background())
	if b.trafficJournal.Epoch != epoch || p.reports[1].TrafficSeq != seq || b.trafficJournal.Pending != nil {
		t.Fatal("journal identity or acknowledgement lost")
	}
	b.report(context.Background())
	if p.total != 1700 {
		t.Fatal("restart lost/recounted traffic", p.total)
	}
	if err := os.WriteFile(b.trafficJournal.path, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	c.pending = 25
	reports := len(p.reports)
	reportingAgent(t, dir, p, c).report(context.Background())
	if len(p.reports) != reports || c.pending != 25 {
		t.Fatal("corrupt journal was silently replaced or counters consumed")
	}
}

func TestTrafficJournalRefusesSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "traffic")); err != nil {
		t.Fatal(err)
	}
	c := &countingCore{fakeCore: fakeCore{name: "test", running: true}, pending: 1000}
	p := &lostResponsePanel{seen: map[uint64]bool{}}
	reportingAgent(t, dir, p, c).report(context.Background())
	if len(p.reports) != 0 || c.pending != 1000 {
		t.Fatal("followed journal directory symlink")
	}
}
