// Package firewall reconciles only provably owned listener allowances.
// It never enables a firewall, changes forwarding policy or removes plain
// operator rules. Unknown legacy allowances are deliberately retained.
package firewall

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type Port struct {
	Proto  string `json:"proto"`
	Port   int    `json:"port"`
	Source string `json:"source,omitempty"`
}

func (p Port) String() string { return strconv.Itoa(p.Port) + "/" + p.Proto }

type Status = spec.FirewallStatus

type entry struct {
	Port     Port   `json:"port"`
	Kind     string `json:"kind"`
	Zone     string `json:"zone,omitempty"`
	Token    string `json:"token"`
	Priority int    `json:"priority"`
}
type ledger struct {
	Version int              `json:"version"`
	Entries map[string]entry `json:"entries"`
	Legacy  []string         `json:"legacy,omitempty"`
}
type Manager struct {
	StateFile string
	Run       func(context.Context, string, ...string) ([]byte, error)
	mu        sync.Mutex
	data      ledger
	loaded    bool
	status    Status
	desired   []Port
}
type boundedOutput struct{ bytes.Buffer }

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 1<<20 {
		return 0, errors.New("firewall output limit exceeded")
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
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("%s operation failed: %w", name, err)
	}
	return out.Bytes(), nil
}
func (m *Manager) Detect(ctx context.Context) string {
	if m.Run == nil && runtime.GOOS != "linux" {
		return ""
	}
	if m.Run != nil || lookPath("ufw") {
		if out, e := m.run(ctx, "ufw", "status"); e == nil && strings.HasPrefix(string(out), "Status: active") {
			return "ufw"
		}
	}
	if m.Run != nil || lookPath("firewall-cmd") {
		if out, e := m.run(ctx, "firewall-cmd", "--state"); e == nil && strings.TrimSpace(string(out)) == "running" {
			return "firewalld"
		}
	}
	return ""
}
func lookPath(s string) bool { _, e := exec.LookPath(s); return e == nil }
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.status
	s.Rules = append([]spec.FirewallRuleStatus(nil), s.Rules...)
	for i := range s.Rules {
		s.Rules[i].Sources = append([]string(nil), s.Rules[i].Sources...)
	}
	return s
}
func (m *Manager) Refresh(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.loaded {
		return nil
	}
	return m.apply(ctx, m.desired)
}

var tokenPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var zonePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func validPort(p Port) bool {
	return p.Port > 0 && p.Port <= 65535 && (p.Proto == "tcp" || p.Proto == "udp")
}
func (m *Manager) load() error {
	if m.loaded {
		return nil
	}
	m.data = ledger{Version: 2, Entries: map[string]entry{}}
	if m.StateFile == "" {
		return errors.New("persistent firewall state is required")
	}
	dir, e := filepath.EvalSymlinks(filepath.Dir(m.StateFile))
	if e != nil {
		return e
	}
	m.StateFile = filepath.Join(dir, filepath.Base(m.StateFile))
	st, e := os.Lstat(m.StateFile)
	if errors.Is(e, os.ErrNotExist) {
		m.loaded = true
		return nil
	}
	if e != nil {
		return e
	}
	owner, ownerOK := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Size() > 1<<20 || st.Mode().Perm()&0022 != 0 || !ownerOK || int(owner.Uid) != os.Geteuid() {
		return errors.New("unsafe firewall state file")
	}
	fd, e := syscall.Open(m.StateFile, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), m.StateFile)
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("firewall state too large")
	}
	if strings.HasPrefix(strings.TrimSpace(string(b)), "[") {
		if e = json.Unmarshal(b, &m.data.Legacy); e != nil {
			return e
		}
	} else if e = json.Unmarshal(b, &m.data); e != nil {
		return e
	}
	if m.data.Version != 2 || m.data.Entries == nil {
		return errors.New("unsupported firewall state")
	}
	for k, v := range m.data.Entries {
		if k != v.Port.String() || !validPort(v.Port) || !tokenPattern.MatchString(v.Token) || (v.Kind != "ufw" && v.Kind != "firewalld") || (v.Kind == "firewalld" && (!zonePattern.MatchString(v.Zone) || v.Priority < 20000 || v.Priority > 29999)) {
			return errors.New("invalid firewall ownership state")
		}
	}
	m.loaded = true
	return nil
}

// Persist intent before running any mutation. Atomic rename + fsync makes a
// crash after an add recoverable without guessing ownership from a plain port.
func (m *Manager) save() error {
	dir := filepath.Dir(m.StateFile)
	for p := dir; ; p = filepath.Dir(p) {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0) || !ok || (int(owner.Uid) != os.Geteuid() && owner.Uid != 0) {
			return errors.New("unsafe firewall state directory")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if st, e := os.Lstat(m.StateFile); e == nil && !st.Mode().IsRegular() {
		return errors.New("unsafe firewall state file")
	} else if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	b, e := json.Marshal(m.data)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".firewall-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(name, m.StateFile); e != nil {
		return e
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (e entry) marker() string { return "bosun-auto-" + e.Token }
func (e entry) rich() string {
	return fmt.Sprintf(`rule priority="%d" port port="%d" protocol="%s" accept`, e.Priority, e.Port.Port, e.Port.Proto)
}
func (m *Manager) cmd(ctx context.Context, e entry, permanent bool, arg string) (string, error) {
	args := []string{"--zone=" + e.Zone}
	if permanent {
		args = append(args, "--permanent")
	}
	args = append(args, arg)
	b, err := m.run(ctx, "firewall-cmd", args...)
	return strings.TrimSpace(string(b)), err
}
func containsLine(s, line string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) == line {
			return true
		}
	}
	return false
}

// UFW prints normalized commands. An unfamiliar rule mentioning this port is
// external: conservatively keep it and do not overwrite its comment/semantics.
func (m *Manager) ufwObserve(ctx context.Context, e entry) (own, other bool, err error) {
	b, err := m.run(ctx, "ufw", "show", "added")
	if err != nil {
		return false, false, err
	}
	pat := regexp.MustCompile(`(^|[^0-9])` + strconv.Itoa(e.Port.Port) + `([^0-9]|$)`)
	prefix := "ufw allow " + e.Port.String() + " comment "
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ufw ") {
			continue
		}
		if strings.HasPrefix(line, prefix) && (strings.TrimPrefix(line, prefix) == "'"+e.marker()+"'" || strings.TrimPrefix(line, prefix) == e.marker()) {
			own = true
			continue
		}
		if (e.Port.Proto == "tcp" && (strings.Contains(line, "/udp") || strings.Contains(line, "proto udp"))) || (e.Port.Proto == "udp" && (strings.Contains(line, "/tcp") || strings.Contains(line, "proto tcp"))) {
			continue
		}
		if pat.MatchString(line) {
			other = true
		}
	}
	return
}
func (m *Manager) syncRule(ctx context.Context, e entry, want bool) (string, error) {
	if e.Kind == "ufw" {
		own, other, err := m.ufwObserve(ctx, e)
		if err != nil {
			return "error", err
		}
		if other {
			if own {
				return "retained", nil
			}
			return "external", nil
		}
		if own == want {
			if want {
				return "synced", nil
			}
			return "removed", nil
		}
		args := []string{"allow", e.Port.String(), "comment", e.marker()}
		if !want {
			args = append([]string{"delete"}, args...)
		}
		if _, err = m.run(ctx, "ufw", args...); err != nil {
			return "error", err
		}
		own, other, err = m.ufwObserve(ctx, e)
		if err != nil {
			return "error", err
		}
		if other || own != want {
			return "error", errors.New("UFW rule could not be verified; existing rules retained")
		}
	} else {
		for _, permanent := range []bool{true, false} {
			rules, err := m.cmd(ctx, e, permanent, "--list-rich-rules")
			if err != nil {
				return "error", err
			}
			own := containsLine(rules, e.rich())
			if own == want {
				continue
			}
			op := "--add-rich-rule="
			if !want {
				op = "--remove-rich-rule="
			}
			if _, err = m.cmd(ctx, e, permanent, op+e.rich()); err != nil {
				return "error", err
			}
			rules, err = m.cmd(ctx, e, permanent, "--list-rich-rules")
			if err != nil {
				return "error", err
			}
			if containsLine(rules, e.rich()) != want {
				return "error", errors.New("firewalld rule verification failed")
			}
		}
	}
	if want {
		return "synced", nil
	}
	return "removed", nil
}
func (m *Manager) Apply(ctx context.Context, ports []Port) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.desired = append([]Port(nil), ports...)
	return m.apply(ctx, ports)
}
func (m *Manager) apply(ctx context.Context, ports []Port) (result error) {
	m.status = Status{CheckedAt: time.Now().Unix(), State: "synced", Rules: []spec.FirewallRuleStatus{}}
	defer func() {
		if result != nil {
			m.status.State = "error"
			m.status.Error = result.Error()
		}
	}()
	if err := m.load(); err != nil {
		return err
	}
	if len(m.data.Legacy) > 0 {
		m.status.Warning = "legacy_rules_retained"
	}
	kind := m.Detect(ctx)
	m.status.Kind = kind
	zone := ""
	if kind == "firewalld" {
		b, e := m.run(ctx, "firewall-cmd", "--get-default-zone")
		if e != nil {
			return e
		}
		zone = strings.TrimSpace(string(b))
		if !zonePattern.MatchString(zone) {
			return errors.New("invalid firewalld zone")
		}
	}
	sources := map[string][]string{}
	wanted := map[string]Port{}
	for _, p := range ports {
		if !validPort(p) {
			return errors.New("invalid firewall listener")
		}
		k := p.String()
		wanted[k] = p
		if p.Source != "" {
			sources[k] = append(sources[k], p.Source)
		}
	}
	keys := map[string]bool{}
	for k := range wanted {
		keys[k] = true
	}
	for k := range m.data.Entries {
		keys[k] = true
	}
	ordered := make([]string, 0, len(keys))
	for k := range keys {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)
	for _, k := range ordered {
		p, want := wanted[k]
		e, owned := m.data.Entries[k]
		if !want {
			p = e.Port
		}
		sort.Strings(sources[k])
		refs := []string{}
		for _, s := range sources[k] {
			if len(refs) == 0 || refs[len(refs)-1] != s {
				refs = append(refs, s)
			}
		}
		row := spec.FirewallRuleStatus{Port: p.Port, Protocol: p.Proto, Sources: refs, State: "pending"}
		operation := func() (string, error) {
			if kind == "" {
				return "unavailable", nil
			}
			if owned && (e.Kind != kind || (kind == "firewalld" && e.Zone != zone)) {
				return "retained", nil
			}
			if !owned {
				var buf [12]byte
				if _, err := rand.Read(buf[:]); err != nil {
					return "error", err
				}
				e = entry{Port: Port{Port: p.Port, Proto: p.Proto}, Kind: kind, Zone: zone, Token: hex.EncodeToString(buf[:]), Priority: 20000 + (int(buf[0])*256+int(buf[1]))%10000}
				if kind == "ufw" {
					_, other, err := m.ufwObserve(ctx, e)
					if err != nil {
						return "error", err
					}
					if other {
						return "external", nil
					}
				} else {
					for _, permanent := range []bool{true, false} {
						plain, err := m.cmd(ctx, e, permanent, "--list-ports")
						if err != nil {
							return "error", err
						}
						for _, v := range strings.Fields(plain) {
							if v == k {
								return "external", nil
							}
						}
						rules, err := m.cmd(ctx, e, permanent, "--list-rich-rules")
						if err != nil {
							return "error", err
						}
						if containsLine(rules, e.rich()) {
							return "external", nil
						}
					}
				}
				m.data.Entries[k] = e
				if err := m.save(); err != nil {
					delete(m.data.Entries, k)
					return "error", err
				}
			}
			state, err := m.syncRule(ctx, e, want)
			if err == nil && !want && (state == "removed" || state == "external") {
				delete(m.data.Entries, k)
				if err = m.save(); err != nil {
					m.data.Entries[k] = e
					return "error", err
				}
			}
			return state, err
		}
		state, err := operation()
		row.State = state
		if err != nil {
			row.Detail = err.Error()
			result = errors.Join(result, err)
		}
		if state == "synced" {
			m.status.Opened++
		}
		if state == "retained" {
			m.status.Warning = "ownership_conflict"
		}
		if state != "removed" {
			m.status.Rules = append(m.status.Rules, row)
		}
	}
	if kind == "" {
		m.status.State = "unavailable"
	}
	return result
}
