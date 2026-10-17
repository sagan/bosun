package reversewg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type modelBackend struct {
	t          *testing.T
	dir        string
	events     []string
	links      map[int]bool
	frozen     bool
	stopped    bool
	failCreate bool
	conflict   bool
	healthy    bool
}

func (b *modelBackend) Preflight(context.Context, []Ownership, []Config) error {
	b.events = append(b.events, "preflight")
	if b.conflict {
		return errors.New("foreign resource")
	}
	return nil
}
func (b *modelBackend) Healthy(context.Context, []Config) bool { return b.healthy }
func (b *modelBackend) Firewall(_ context.Context, s string) error {
	b.frozen = strings.Contains(s, "ip saddr 10.10.0.5 drop")
	if b.frozen {
		b.events = append(b.events, "freeze")
	} else {
		b.events = append(b.events, "open")
	}
	return nil
}
func (b *modelBackend) Remove(_ context.Context, o Ownership) error {
	if !b.frozen || !b.stopped {
		b.t.Fatal("removed resources before freezing and quiescing")
	}
	delete(b.links, o.Slot)
	b.events = append(b.events, "remove")
	return nil
}
func (b *modelBackend) Create(_ context.Context, c Config) error {
	if !b.frozen || !b.stopped {
		b.t.Fatal("created resources before freezing and quiescing")
	}
	rs, err := readJournal(b.dir)
	if err != nil {
		b.t.Fatal(err)
	}
	found := false
	for _, r := range rs {
		found = found || r.Slot == c.Slot
	}
	if !found {
		b.t.Fatal("created resource without durable ownership")
	}
	b.links[c.Slot] = true
	b.events = append(b.events, "create")
	if b.failCreate {
		return errors.New("simulated failure after interface creation")
	}
	return nil
}
func (b *modelBackend) stop(ctx context.Context) error {
	if ctx.Err() != nil {
		b.t.Fatal("quiesce received canceled request context")
	}
	b.stopped = true
	b.events = append(b.events, "stop")
	return nil
}

func TestReconcileCrashRecoveryAndEmptyStartup(t *testing.T) {
	a, _ := pair(t)
	dir := t.TempDir()
	b := &modelBackend{t: t, dir: dir, links: map[int]bool{}, failCreate: true}
	m := &Manager{Dir: dir, Backend: b}
	changed, err := m.Reconcile(context.Background(), []Config{a}, b.stop)
	if !changed || err == nil || !b.frozen || !b.links[a.Slot] {
		t.Fatal("partial failure not modeled")
	}
	data, err := os.ReadFile(filepath.Join(dir, "reversewg-owned.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), a.PrivateKey) || strings.Contains(string(data), a.PeerKey) {
		t.Fatal("journal contains credentials")
	}
	st, _ := os.Stat(filepath.Join(dir, "reversewg-owned.json"))
	if st.Mode().Perm() != 0600 {
		t.Fatal("journal permissions")
	}
	// Simulate process death after a partial apply; the empty desired state
	// must still remove persisted resources rather than returning a no-op.
	b.failCreate = false
	b.events = nil
	b.stopped = false
	m = &Manager{Dir: dir, Backend: b}
	changed, err = m.Reconcile(context.Background(), nil, b.stop)
	if err != nil || !changed || len(b.links) != 0 || b.frozen {
		t.Fatalf("recovery: %v", err)
	}
	if !reflect.DeepEqual(b.events, []string{"preflight", "freeze", "stop", "remove", "open"}) {
		t.Fatal(b.events)
	}
	rs, err := readJournal(dir)
	if err != nil || len(rs) != 0 {
		t.Fatal("ownership survived successful removal")
	}
}

func TestReconcileNoopRepairAndRevocation(t *testing.T) {
	a, _ := pair(t)
	b := &modelBackend{t: t, dir: t.TempDir(), links: map[int]bool{}, healthy: true}
	m := &Manager{Dir: b.dir, Backend: b}
	if _, err := m.Reconcile(context.Background(), []Config{a}, b.stop); err != nil {
		t.Fatal(err)
	}
	b.events = nil
	b.stopped = false
	if changed, err := m.Reconcile(context.Background(), []Config{a}, b.stop); err != nil || changed {
		t.Fatal("healthy no-op restarts proxy")
	}
	if !reflect.DeepEqual(b.events, []string{"open"}) {
		t.Fatal(b.events)
	}
	b.healthy = false
	b.events = nil
	if changed, err := m.Reconcile(context.Background(), []Config{a}, b.stop); err != nil || !changed {
		t.Fatal("missing kernel state not repaired")
	}
	// A bad replacement cannot keep the old proxy running, even if the
	// request was canceled before its validation failed.
	a.PrivateKey = "invalid"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.stopped = false
	if changed, err := m.Reconcile(ctx, []Config{a}, b.stop); err == nil || !changed || !b.stopped || !b.frozen {
		t.Fatal("invalid replacement kept old configuration active")
	}
}

func TestJournalAndForeignResources(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "reversewg-owned.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := readJournal(dir); err == nil {
		t.Fatal("read followed symlink")
	}
	if err := saveJournal(dir, []Ownership{{Slot: 1}}); err == nil {
		t.Fatal("write followed symlink")
	}
	bts, _ := os.ReadFile(target)
	if string(bts) != "keep" {
		t.Fatal("foreign file changed")
	}
	a, _ := pair(t)
	b := &modelBackend{t: t, dir: t.TempDir(), links: map[int]bool{}, conflict: true}
	m := &Manager{Dir: b.dir, Backend: b}
	if _, err := m.Reconcile(context.Background(), []Config{a}, b.stop); err == nil {
		t.Fatal("foreign resource accepted")
	}
	if _, err := os.Stat(filepath.Join(b.dir, "reversewg-owned.json")); !os.IsNotExist(err) {
		t.Fatal("claimed foreign resource")
	}
	if !reflect.DeepEqual(b.events, []string{"preflight"}) {
		t.Fatal(b.events)
	}
}
