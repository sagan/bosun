package reversewg

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Backend must refuse foreign resources, replace firewall rules atomically,
// and remove only the exact resources described by an ownership record.
type Backend interface {
	Preflight(context.Context, []Ownership, []Config) error
	Healthy(context.Context, []Config) bool
	Firewall(context.Context, string) error
	Remove(context.Context, Ownership) error
	Create(context.Context, Config) error
}

type Manager struct {
	Dir     string
	Backend Backend
	mu      sync.Mutex
	applied [32]byte
	synced  bool
}

// Reconcile returns changed=true when quiesce was called and the caller must
// restore its proxy processes from the successfully applied desired state.
// Quiesce must checkpoint traffic and stop all processes holding old sockets.
// Any error leaves the caller responsible for keeping those processes stopped.
func (m *Manager) Reconcile(ctx context.Context, desired []Config, quiesce func(context.Context) error) (changed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	safetyCtx := context.WithoutCancel(ctx)
	if quiesce != nil {
		stop := quiesce
		quiesce = func(c context.Context) error {
			c, cancel := context.WithTimeout(c, 20*time.Second)
			defer cancel()
			return stop(c)
		}
	}
	old, err := readJournal(m.Dir)
	if err != nil {
		m.synced = false
		var freezeErr error
		if backend, ok := m.Backend.(interface{ EmergencyFreeze(context.Context) error }); ok {
			freezeErr = backend.EmergencyFreeze(safetyCtx)
		}
		if quiesce != nil {
			return true, errors.Join(err, freezeErr, quiesce(safetyCtx))
		}
		return false, err
	}
	if len(desired) == 0 && len(old) == 0 {
		return false, nil
	}
	if m.Backend == nil || quiesce == nil {
		return false, fmt.Errorf("reverse WireGuard requires a backend and a quiesce callback")
	}
	cs := append([]Config(nil), desired...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].Slot < cs[j].Slot })
	rules, validationErr := Firewall(cs)
	if len(cs) > 64 {
		validationErr = fmt.Errorf("at most 64 reverse WireGuard links per node")
	}
	if validationErr != nil {
		// Invalid replacement must not leave the previous grant running.
		if len(old) > 0 {
			f, _ := FrozenFirewall(old)
			freezeErr := m.Backend.Firewall(safetyCtx, f)
			stopErr := quiesce(safetyCtx)
			m.synced = false
			return true, errors.Join(validationErr, freezeErr, stopErr)
		}
		return false, validationErr
	}
	encoded, _ := json.Marshal(cs)
	key := sha256.Sum256(encoded)
	if m.synced && m.applied == key && m.Backend.Healthy(ctx, cs) {
		// Restore externally lost/edited rules even when desired state is unchanged.
		if err := m.Backend.Firewall(ctx, rules); err == nil {
			return false, nil
		}
		// A failed refresh takes the same stop/freeze path as a changed state.
	}
	pending := append([]Ownership(nil), old...)
	seen := map[int]Ownership{}
	for _, o := range old {
		seen[o.Slot] = o
	}
	for _, o := range ownership(cs) {
		if prev, ok := seen[o.Slot]; ok {
			if prev.Exit != o.Exit {
				f, _ := FrozenFirewall(old)
				freezeErr := m.Backend.Firewall(safetyCtx, f)
				stopErr := quiesce(safetyCtx)
				m.synced = false
				return true, errors.Join(fmt.Errorf("remove the old WireGuard role before reusing its slot"), freezeErr, stopErr)
			}
		} else {
			pending = append(pending, o)
			seen[o.Slot] = o
		}
	}
	// Reject collisions before claiming ownership of new slots in the journal.
	if err := m.Backend.Preflight(ctx, old, cs); err != nil {
		if len(old) > 0 {
			f, _ := FrozenFirewall(old)
			freezeErr := m.Backend.Firewall(safetyCtx, f)
			stopErr := quiesce(safetyCtx)
			m.synced = false
			return true, errors.Join(err, freezeErr, stopErr)
		}
		return false, err
	}
	if err := saveJournal(m.Dir, pending); err != nil {
		f, _ := FrozenFirewall(old)
		freezeErr := m.Backend.Firewall(safetyCtx, f)
		stopErr := quiesce(safetyCtx)
		m.synced = false
		return true, errors.Join(err, freezeErr, stopErr)
	}
	m.synced = false
	frozen, _ := FrozenFirewall(pending)
	freezeErr := m.Backend.Firewall(safetyCtx, frozen)
	stopErr := quiesce(safetyCtx)
	if freezeErr != nil || stopErr != nil {
		return true, errors.Join(freezeErr, stopErr)
	}
	// Keep the pending journal until removal and all creation steps complete.
	// A crash at any point causes startup to freeze and retry the entire set.
	for _, o := range pending {
		if err := m.Backend.Remove(ctx, o); err != nil {
			return true, err
		}
	}
	for _, c := range cs {
		if err := m.Backend.Create(ctx, c); err != nil {
			return true, err
		}
	}
	if err := m.Backend.Firewall(ctx, rules); err != nil {
		return true, err
	}
	if err := saveJournal(m.Dir, ownership(cs)); err != nil {
		freezeErr := m.Backend.Firewall(safetyCtx, frozen)
		return true, errors.Join(err, freezeErr)
	}
	m.applied, m.synced = key, true
	return true, nil
}

// Freeze closes owned data paths without destroying their recovery inventory.
// It is used when a later proxy/shaping step fails after transport succeeded.
func (m *Manager) Freeze(ctx context.Context, quiesce func(context.Context) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.synced = false
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	old, err := readJournal(m.Dir)
	var freezeErr error
	if err == nil && len(old) > 0 {
		rules, _ := FrozenFirewall(old)
		if m.Backend != nil {
			freezeErr = m.Backend.Firewall(ctx, rules)
		}
	} else if err != nil {
		if b, ok := m.Backend.(interface{ EmergencyFreeze(context.Context) error }); ok {
			freezeErr = b.EmergencyFreeze(ctx)
		}
	}
	var stopErr error
	if quiesce != nil {
		stopErr = quiesce(ctx)
	}
	return errors.Join(err, freezeErr, stopErr)
}
