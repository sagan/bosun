// Package wgfirewall manages host-firewall allowances for reverse WireGuard
// exit forwarding. The reversewg nft ACL must already protect every managed
// interface: these allowances never replace its destination and reply checks.
// Operator rules managed through UFW's persistent configuration are preserved.
// UFW itself rebuilds its user/logging chains on deletion; direct runtime-only writes
// inside those UFW-managed chains are outside this backend's supported scope.
package wgfirewall

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type RuleStatus struct {
	Rule
	State string `json:"state"`
}

type Status struct {
	CheckedAt int64        `json:"checked_at"`
	Backend   string       `json:"backend"`
	State     string       `json:"state"`
	Reason    string       `json:"reason,omitempty"`
	Rules     []RuleStatus `json:"rules"`
}

type Manager struct {
	StateFile  string
	Run        func(context.Context, string, ...string) ([]byte, error)
	mu         sync.Mutex
	loaded     bool
	data       journal
	status     Status
	desired    []spec.WireGuardLink
	desiredSet bool
	observed   *ufwSnapshot // scoped to one serialized reconciliation
}

type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 8<<20 {
		return 0, errors.New("command_output_limit")
	}
	return b.Buffer.Write(p)
}

func (m *Manager) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if m.Run != nil {
		return m.Run(ctx, name, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.WaitDelay = time.Second
	var output boundedOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	return output.Bytes(), err
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Rules = append([]RuleStatus(nil), s.Rules...)
	return s
}

func (m *Manager) Apply(ctx context.Context, links []spec.WireGuardLink) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desiredSet = true
	m.desired = make([]spec.WireGuardLink, len(links))
	for i, c := range links {
		// Retain only policy, never transport private keys or public endpoints.
		m.desired[i] = spec.WireGuardLink{Slot: c.Slot, Exit: c.Exit}
		if c.PrivateAccess != nil {
			p := *c.PrivateAccess
			p.Rules = append([]spec.PrivateAccessRule(nil), p.Rules...)
			m.desired[i].PrivateAccess = &p
		}
	}
	err := m.apply(ctx)
	if err != nil {
		m.desired, m.desiredSet = nil, false
	}
	return err
}

func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.desiredSet {
		return nil
	}
	err := m.apply(ctx)
	if err != nil {
		m.desired, m.desiredSet = nil, false
	}
	return err
}

func (m *Manager) detect(ctx context.Context) (string, error) {
	if m.Run == nil && runtime.GOOS != "linux" {
		return "", nil
	}
	ufw, firewalld := false, false
	if _, err := exec.LookPath("ufw"); m.Run != nil || err == nil {
		b, err := m.run(ctx, "ufw", "status")
		if err != nil {
			return "", errors.New("ufw_status_failed")
		}
		s := string(b)
		if !strings.HasPrefix(s, "Status: active") && !strings.HasPrefix(s, "Status: inactive") {
			return "", errors.New("ufw_status_invalid")
		}
		ufw = strings.HasPrefix(s, "Status: active")
	}
	if _, err := exec.LookPath("firewall-cmd"); m.Run != nil || err == nil {
		b, err := m.run(ctx, "firewall-cmd", "--state")
		firewalld = err == nil && strings.TrimSpace(string(b)) == "running"
		if !firewalld && strings.TrimSpace(string(b)) != "not running" {
			return "", errors.New("firewalld_status_invalid")
		}
	}
	if ufw && firewalld {
		return "multiple", nil
	}
	if firewalld {
		return "firewalld", nil
	}
	if ufw {
		return "ufw", nil
	}
	return "", nil
}

func (m *Manager) apply(ctx context.Context) (result error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	m.observed = nil
	defer func() { m.observed = nil }()
	m.status = Status{CheckedAt: time.Now().Unix(), State: "synced", Rules: []RuleStatus{}}
	defer func() {
		if result != nil {
			if m.status.State != "unsupported" {
				m.status.State = "error"
			}
			m.status.Reason = result.Error()
		}
	}()
	hasExit := false
	for _, c := range m.desired {
		hasExit = hasExit || c.Exit
	}
	if !hasExit && !m.loaded {
		if _, err := os.Lstat(m.StateFile); m.StateFile == "" || errors.Is(err, os.ErrNotExist) {
			m.status.State = "not_required"
			return nil
		}
	}
	if err := m.load(); err != nil {
		return err
	}
	if !hasExit {
		m.status.Backend = "ufw"
		return m.removeStale(ctx, nil)
	}
	backend, err := m.detect(ctx)
	if err != nil {
		return err
	}
	m.status.Backend = backend
	if backend == "firewalld" || backend == "multiple" {
		m.status.State = "unsupported"
		return errors.New("forwarding_backend_unsupported")
	}
	if backend == "" {
		m.status.State = "not_required"
		if len(m.data.Entries) > 0 {
			m.status.Reason = "inactive_backend_rules_retained"
		}
		return nil
	}
	wanted, err := m.desiredRules(ctx, m.desired)
	if err != nil {
		return err
	}
	// Preflight every selector before any mutation. UFW treats differences in
	// logging/action/comment as updates of the same rule, so a late conflicting
	// selector must not cause earlier partial additions or operator replacement.
	for _, r := range wanted {
		e, exists := m.data.Entries[r.key()]
		if !exists {
			e = entry{Rule: r}
		}
		own, _, conflict, err := m.observe(ctx, e)
		if err != nil {
			return err
		}
		if conflict || (!exists && own) {
			return errors.New("ufw_forward_rule_conflict")
		}
	}
	// Revoke stale allowances before adding any new ones, including route moves.
	if err := m.removeStale(ctx, wanted); err != nil {
		return err
	}
	for _, k := range sortedKeys(wanted) {
		r := wanted[k]
		e, exists := m.data.Entries[k]
		if !exists {
			var token [12]byte
			if _, err := rand.Read(token[:]); err != nil {
				return errors.New("ownership_token_failed")
			}
			e = entry{Rule: r, Token: hex.EncodeToString(token[:])}
			own, external, conflict, err := m.observe(ctx, e)
			if err != nil {
				return err
			}
			if conflict || own {
				return errors.New("ufw_forward_rule_conflict")
			}
			if external {
				if err := m.verifyLive(ctx, r, 1); err != nil {
					return err
				}
				m.status.State = "external"
				m.status.Rules = append(m.status.Rules, RuleStatus{r, "external"})
				continue
			}
			if count, err := m.liveCount(ctx, r); err != nil {
				return err
			} else if count != 0 {
				return errors.New("ufw_forward_runtime_rule_unowned")
			}
			m.data.Entries[k] = e
			if err := m.save(); err != nil {
				delete(m.data.Entries, k)
				return err
			}
		}
		state, err := m.sync(ctx, e, true)
		m.status.Rules = append(m.status.Rules, RuleStatus{r, state})
		if err != nil {
			return err
		}
		if state == "external" {
			m.status.State = "external"
		}
	}
	return nil
}

func (m *Manager) removeStale(ctx context.Context, wanted map[string]Rule) error {
	for _, k := range sortedKeys(m.data.Entries) {
		if _, ok := wanted[k]; ok {
			continue
		}
		e := m.data.Entries[k]
		state, err := m.sync(ctx, e, false)
		if err != nil {
			m.status.Rules = append(m.status.Rules, RuleStatus{e.Rule, state})
			return err
		}
		if state == "retained" {
			m.status.Rules = append(m.status.Rules, RuleStatus{e.Rule, state})
			return errors.New("owned_rule_changed_retained")
		}
		delete(m.data.Entries, k)
		if err := m.save(); err != nil {
			m.data.Entries[k] = e
			return err
		}
	}
	return nil
}
