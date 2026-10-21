package wgfirewall

import (
	"context"
	"errors"
	"net/netip"
	"strings"
)

// Parse only UFW's explicit route syntax. Clause order is not significant;
// host prefixes and omitted any selectors are normalized. Unknown syntax is
// never treated as proof of ownership.
func parseUFW(line string) (Rule, string, string, bool) {
	var r Rule
	r.Source, r.Destination = "any", "any"
	comment := ""
	if i := strings.Index(line, " comment "); i >= 0 {
		comment = strings.Trim(strings.TrimSpace(line[i+9:]), "'\"")
		line = line[:i]
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "ufw" || f[1] != "route" {
		return r, comment, "", false
	}
	action := f[2]
	for i := 3; i < len(f); {
		switch f[i] {
		case "log", "log-all":
			action += " " + f[i]
			i++
		case "in", "out":
			if i+2 >= len(f) || f[i+1] != "on" {
				return r, comment, action, false
			}
			if f[i] == "in" {
				r.In = f[i+2]
			} else {
				r.Out = f[i+2]
			}
			i += 3
		case "proto":
			if i+1 >= len(f) {
				return r, comment, action, false
			}
			r.Protocol = f[i+1]
			i += 2
		case "from", "to":
			if i+1 >= len(f) {
				return r, comment, action, false
			}
			source, addr := f[i] == "from", normalizeAddress(f[i+1])
			if source {
				r.Source = addr
			} else {
				r.Destination = addr
			}
			i += 2
			if i < len(f) && f[i] == "port" {
				if i+1 >= len(f) {
					return r, comment, action, false
				}
				if source {
					r.SourcePort = f[i+1]
				} else {
					r.DestinationPort = f[i+1]
				}
				i += 2
			}
		default:
			return r, comment, action, false
		}
	}
	return r, comment, action, true
}

func normalizeAddress(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		if p.Bits() == 0 {
			return "any"
		}
		if p.Bits() == p.Addr().BitLen() {
			return p.Addr().String()
		}
		return p.Masked().String()
	}
	return s
}

func sameRule(a, b Rule) bool {
	return selectorKey(a) == selectorKey(b)
}

func selectorKey(r Rule) string {
	r.Slot = 0
	r.Source, r.Destination = normalizeAddress(r.Source), normalizeAddress(r.Destination)
	return r.key()
}

type ufwObservation struct {
	rule           Rule
	marker, action string
	valid          bool
}

type ufwSnapshot struct {
	selectors map[string][]ufwObservation
	markers   map[string][]ufwObservation
	runtime   map[bool]map[string]int
}

// Read one snapshot for unchanged reconciliations. Mutations invalidate it so
// every add/delete is still verified against fresh persistent and live state.
// This avoids two UFW processes per rule on every periodic refresh.
func (m *Manager) snapshot(ctx context.Context) (*ufwSnapshot, error) {
	if m.observed != nil {
		return m.observed, nil
	}
	b, err := m.run(ctx, "ufw", "show", "added")
	if err != nil {
		return nil, errors.New("ufw_forward_rules_query_failed")
	}
	s := &ufwSnapshot{selectors: map[string][]ufwObservation{}, markers: map[string][]ufwObservation{}, runtime: map[bool]map[string]int{}}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		r, marker, action, ok := parseUFW(line)
		if strings.HasPrefix(line, "ufw route ") && !ok {
			return nil, errors.New("ufw_forward_rule_syntax_unsupported")
		}
		o := ufwObservation{r, marker, action, ok}
		if marker != "" {
			s.markers[marker] = append(s.markers[marker], o)
		}
		if ok {
			k := selectorKey(r)
			s.selectors[k] = append(s.selectors[k], o)
		}
	}
	m.observed = s
	return s, nil
}

// UFW status is also rendered from its persistent rule objects. UFW's user
// comments are not installed as kernel comments, so ownership comes only from
// show added + our journal. The actual kernel must independently contain one
// exact ACCEPT tuple in UFW's forwarding chain before we report or revoke it.
func parseLiveUFW(line, chain string) (Rule, bool) {
	r := Rule{Source: "any", Destination: "any"}
	f := strings.Fields(line)
	if len(f) < 4 || f[0] != "-A" || f[1] != chain {
		return r, false
	}
	target := ""
	module := ""
	seen := map[string]bool{}
	for i := 2; i < len(f); i += 2 {
		if i+1 >= len(f) || seen[f[i]] {
			return r, false
		}
		seen[f[i]] = true
		switch f[i] {
		case "-i":
			r.In = f[i+1]
		case "-o":
			r.Out = f[i+1]
		case "-s":
			r.Source = normalizeAddress(f[i+1])
		case "-d":
			r.Destination = normalizeAddress(f[i+1])
		case "-p":
			r.Protocol = f[i+1]
		case "--sport", "--sports":
			r.SourcePort = f[i+1]
		case "--dport", "--dports":
			r.DestinationPort = f[i+1]
		case "-m":
			module = f[i+1]
		case "-j":
			target = f[i+1]
		default:
			return r, false
		}
	}
	return r, target == "ACCEPT" && (r.Protocol == "tcp" || r.Protocol == "udp") && (module == "" || module == r.Protocol || (module == "multiport" && (r.SourcePort != "" || r.DestinationPort != ""))) && validPort(r.SourcePort) && validPort(r.DestinationPort)
}

func (m *Manager) liveCount(ctx context.Context, r Rule) (int, error) {
	s, err := m.snapshot(ctx)
	if err != nil {
		return 0, err
	}
	v6 := strings.Contains(r.Source, ":") || strings.Contains(r.Destination, ":")
	if _, ok := s.runtime[v6]; !ok {
		name, chain := "iptables", "ufw-user-forward"
		if v6 {
			name, chain = "ip6tables", "ufw6-user-forward"
		}
		b, err := m.run(ctx, name, "-w", "2", "-S")
		if err != nil {
			return 0, errors.New("ufw_forward_runtime_query_failed")
		}
		counts := map[string]int{}
		for _, line := range strings.Split(string(b), "\n") {
			if live, ok := parseLiveUFW(line, chain); ok {
				counts[selectorKey(live)]++
			}
		}
		s.runtime[v6] = counts
	}
	return s.runtime[v6][selectorKey(r)], nil
}

func (m *Manager) verifyLive(ctx context.Context, r Rule, want int) error {
	count, err := m.liveCount(ctx, r)
	if err != nil {
		return err
	}
	if count != want {
		return errors.New("ufw_forward_runtime_verification_failed")
	}
	return nil
}

func (m *Manager) observe(ctx context.Context, e entry) (own, external, conflict bool, err error) {
	s, err := m.snapshot(ctx)
	if err != nil {
		return false, false, false, err
	}
	for _, o := range s.markers[e.marker()] {
		if !o.valid || o.action != "allow" || !sameRule(o.rule, e.Rule) || own {
			conflict = true
		} else {
			own = true
		}
	}
	for _, o := range s.selectors[selectorKey(e.Rule)] {
		if o.marker == e.marker() {
			continue
		}
		if o.action == "allow" {
			external = true
		} else {
			conflict = true
		}
	}
	return own, external, conflict, nil
}

func (m *Manager) sync(ctx context.Context, e entry, want bool) (string, error) {
	own, external, conflict, err := m.observe(ctx, e)
	if err != nil {
		return "error", err
	}
	if conflict || (own && external) {
		if !want {
			return "retained", nil
		}
		return "error", errors.New("ufw_forward_rule_conflict")
	}
	if external {
		if err := m.verifyLive(ctx, e.Rule, 1); err != nil {
			return "error", err
		}
		return "external", nil
	}
	if own != want {
		if !want {
			if err := m.verifyLive(ctx, e.Rule, 1); err != nil {
				return "retained", err
			}
		}
		args := e.Rule.args()
		if !want {
			// route delete is UFW's supported routed-rule deletion syntax.
			args = append([]string{"route", "delete"}, args[1:]...)
		}
		args = append(args, "comment", e.marker())
		if _, err := m.run(ctx, "ufw", args...); err != nil {
			return "error", errors.New("ufw_forward_rule_update_failed")
		}
		m.observed = nil
		own, external, conflict, err = m.observe(ctx, e)
		if err != nil || conflict || external || own != want {
			return "error", errors.New("ufw_forward_rule_verification_failed")
		}
	}
	count := 0
	if want {
		count = 1
	}
	if err := m.verifyLive(ctx, e.Rule, count); err != nil {
		return "error", err
	}
	if want {
		return "synced", nil
	}
	return "removed", nil
}
