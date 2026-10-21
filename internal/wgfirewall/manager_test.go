package wgfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fixture struct {
	state         string
	backend       string
	rules         []string
	routes4       string
	routes6       string
	policies      string
	calls         []string
	failAfterAdd  bool
	mutations     int
	intentChecked bool
	liveMode      string
}

func (f *fixture) run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if name == "iptables" || name == "ip6tables" {
		var lines []string
		for _, s := range f.rules {
			r, _, action, ok := parseUFW(s)
			if !ok || action != "allow" {
				continue
			}
			v6 := strings.Contains(r.Source, ":") || strings.Contains(r.Destination, ":")
			if v6 != (name == "ip6tables") {
				continue
			}
			chain := "ufw-user-forward"
			if v6 {
				chain = "ufw6-user-forward"
			}
			line := "-A " + chain + " -i " + r.In + " -o " + r.Out + " -p " + r.Protocol
			if r.Source != "any" {
				line += " -s " + r.Source
			}
			if r.Destination != "any" {
				line += " -d " + r.Destination
			}
			if r.SourcePort != "" || r.DestinationPort != "" {
				line += " -m " + r.Protocol
			}
			if r.SourcePort != "" {
				line += " --sport " + r.SourcePort
			}
			if r.DestinationPort != "" {
				line += " --dport " + r.DestinationPort
			}
			line += " -j ACCEPT"
			switch f.liveMode {
			case "missing":
				continue
			case "duplicate":
				lines = append(lines, line)
			case "extra-selector":
				line += " -m conntrack --ctstate ESTABLISHED"
			}
			lines = append(lines, line)
		}
		return []byte(strings.Join(lines, "\n")), nil
	}
	if name == "ip" {
		if args[2] == "rule" {
			if f.policies != "" {
				return []byte(f.policies), nil
			}
			return []byte(`[{"priority":0,"src":"all","table":"local"},{"priority":32766,"src":"all","table":"main"},{"priority":32767,"src":"all","table":"default"}]`), nil
		}
		if args[1] == "-6" {
			return []byte(f.routes6), nil
		}
		return []byte(f.routes4), nil
	}
	if name == "firewall-cmd" {
		if f.backend == "firewalld" || f.backend == "both" {
			return []byte("running"), nil
		}
		return []byte("not running"), errors.New("inactive")
	}
	if name != "ufw" {
		return nil, errors.New("unexpected executable")
	}
	if args[0] == "status" {
		if f.backend != "ufw" && f.backend != "both" {
			return []byte("Status: inactive"), nil
		}
		return []byte("Status: active\n" + strings.Join(f.rules, "\n")), nil
	}
	if args[0] == "show" {
		return []byte(strings.Join(f.rules, "\n")), nil
	}
	if args[0] != "route" {
		return nil, errors.New("unexpected mutation")
	}
	del := args[1] == "delete"
	if del {
		args = append([]string{"route"}, args[2:]...)
	}
	line := "ufw " + strings.Join(args, " ")
	r, marker, action, ok := parseUFW(line)
	if !ok || action != "allow" {
		return nil, errors.New("invalid route operation")
	}
	// Assert durable intent exists before even the first actual mutation.
	b, err := os.ReadFile(f.state)
	var j journal
	if err != nil || json.Unmarshal(b, &j) != nil {
		return nil, errors.New("missing durable intent")
	}
	intent := false
	for _, e := range j.Entries {
		intent = intent || (e.marker() == marker && sameRule(e.Rule, r))
	}
	if !intent {
		return nil, errors.New("mutation lacks ownership intent")
	}
	f.intentChecked = true
	f.mutations++
	if del {
		for i, s := range f.rules {
			_, mark, _, _ := parseUFW(s)
			if mark == marker {
				f.rules = append(f.rules[:i], f.rules[i+1:]...)
				break
			}
		}
	} else {
		// Use a different clause order and /32 host rendering from the request.
		if !strings.Contains(r.Source, ":") && r.Source != "any" && !strings.Contains(r.Source, "/") {
			r.Source += "/32"
		}
		line = "ufw route allow out on " + r.Out + " in on " + r.In + " from " + r.Source
		if r.SourcePort != "" {
			line += " port " + r.SourcePort
		}
		line += " to " + r.Destination
		if r.DestinationPort != "" {
			line += " port " + r.DestinationPort
		}
		line += " proto " + r.Protocol + " comment '" + marker + "'"
		f.rules = append(f.rules, line)
		if f.failAfterAdd {
			f.failAfterAdd = false
			return nil, errors.New("simulated crash after kernel mutation")
		}
	}
	return nil, nil
}

func manager(t *testing.T) (*Manager, *fixture) {
	t.Helper()
	f := &fixture{backend: "ufw", routes4: `[{"dst":"default","dev":"wan0"}]`, routes6: `[]`}
	m := &Manager{StateFile: filepath.Join(t.TempDir(), "wg-firewall.json"), Run: f.run}
	f.state = m.StateFile
	return m, f
}

func link() spec.WireGuardLink { return spec.WireGuardLink{Slot: 1, Exit: true} }

func TestScopedBidirectionalRulesAndRestartCleanup(t *testing.T) {
	m, f := manager(t)
	if err := m.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 4 || !f.intentChecked || m.Status().State != "synced" {
		t.Fatalf("%+v %+v", m.Status(), f.rules)
	}
	for _, s := range f.rules {
		r, _, _, _ := parseUFW(s)
		if !((r.In == "bwg1" && r.Out == "wan0" && normalizeAddress(r.Source) == "10.10.0.5") || (r.In == "wan0" && r.Out == "bwg1" && r.Destination == "10.10.0.5")) {
			t.Fatal(s)
		}
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			t.Fatal(s)
		}
	}
	before := f.mutations
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.mutations != before {
		t.Fatal("refresh mutated unchanged rules")
	}
	m2 := &Manager{StateFile: m.StateFile, Run: f.run}
	if err := m2.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 0 {
		t.Fatal(f.rules)
	}
}

func TestManualEquivalentNeverAdoptedAndNarrowRulesPreserved(t *testing.T) {
	m, f := manager(t)
	manual := "ufw route allow in on bwg1 out on wan0 from 10.10.0.5 proto tcp"
	narrow := "ufw route allow in on bwg1 out on wan0 from 10.10.0.5 to 203.0.113.30 port 443 proto tcp comment 'operator'"
	f.rules = []string{manual, narrow}
	if err := m.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
		t.Fatal(err)
	}
	if m.Status().State != "external" || len(m.data.Entries) != 3 {
		t.Fatalf("%+v", m.Status())
	}
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 2 || f.rules[0] != manual || f.rules[1] != narrow {
		t.Fatal(f.rules)
	}
}

func TestCrashAfterAddRecoveredWithoutDuplicateOrOwnershipLoss(t *testing.T) {
	m, f := manager(t)
	f.failAfterAdd = true
	if m.Apply(context.Background(), []spec.WireGuardLink{link()}) == nil {
		t.Fatal("expected failure")
	}
	before := f.mutations
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.mutations != before {
		t.Fatal("failed apply retained desired state")
	}
	m2 := &Manager{StateFile: m.StateFile, Run: f.run}
	if err := m2.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 4 {
		t.Fatal(f.rules)
	}
	if err := m2.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 0 {
		t.Fatal(f.rules)
	}
}

func TestExternallyEditedOwnedRuleRetained(t *testing.T) {
	m, f := manager(t)
	if err := m.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
		t.Fatal(err)
	}
	f.rules[0] = strings.Replace(f.rules[0], "wan0", "operator0", 1)
	modified := f.rules[0]
	if m.Apply(context.Background(), nil) == nil {
		t.Fatal("edited rule must report cleanup conflict")
	}
	found := false
	for _, s := range f.rules {
		found = found || s == modified
	}
	if !found {
		t.Fatal("edited rule removed")
	}
}

func TestPrivateRouteAndIPv6RespectDestinationAndPorts(t *testing.T) {
	m, f := manager(t)
	f.routes4 = `[{"dst":"default","dev":"wan0"},{"dst":"192.168.0.0/16","dev":"lan0"}]`
	f.routes6 = `[{"dst":"default","dev":"wan6"}]`
	c := link()
	c.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "192.168.10.0/24", Protocol: "tcp", PortStart: 443}}}
	if err := m.Apply(context.Background(), []spec.WireGuardLink{c}); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 10 {
		t.Fatal(f.rules)
	}
	forward, reply, v6 := false, false, false
	for _, s := range f.rules {
		r, _, _, _ := parseUFW(s)
		forward = forward || (r.Out == "lan0" && r.Destination == "192.168.10.0/24" && r.DestinationPort == "443" && r.Protocol == "tcp")
		reply = reply || (r.In == "lan0" && r.Source == "192.168.10.0/24" && r.SourcePort == "443" && r.Protocol == "tcp")
		v6 = v6 || (r.Out == "wan6" && r.Source == "fd42:626f:7375::5")
	}
	if !forward || !reply || !v6 {
		t.Fatal(f.rules)
	}
}

func TestAmbiguousRoutesAndPolicyFailWithoutMutations(t *testing.T) {
	for _, scenario := range []string{"multipath", "split-private", "policy", "missing"} {
		t.Run(scenario, func(t *testing.T) {
			m, f := manager(t)
			c := link()
			switch scenario {
			case "multipath":
				f.routes4 = `[{"dst":"default","dev":"wan0"},{"dst":"default","dev":"wan1"}]`
			case "split-private":
				f.routes4 = `[{"dst":"default","dev":"wan0"},{"dst":"192.168.0.0/16","dev":"lan0"},{"dst":"192.168.10.0/24","dev":"lan1"}]`
				c.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "192.168.0.0/16"}}}
			case "policy":
				f.policies = `[{"priority":100,"src":"all","table":"100"}]`
			case "missing":
				f.routes4 = `[]`
			}
			if m.Apply(context.Background(), []spec.WireGuardLink{c}) == nil {
				t.Fatal("expected route error")
			}
			if f.mutations != 0 {
				t.Fatal("unsafe routes mutated firewall")
			}
		})
	}
}

func TestEmptyNewNodeNoopAndUnsupportedBackendCleanup(t *testing.T) {
	m := &Manager{StateFile: filepath.Join(t.TempDir(), "absent", "journal"), Run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unexpected command")
		return nil, nil
	}}
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	m, f := manager(t)
	if err := m.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
		t.Fatal(err)
	}
	f.backend = "both"
	if m.Apply(context.Background(), []spec.WireGuardLink{link()}) == nil || m.Status().State != "unsupported" {
		t.Fatal(m.Status())
	}
	// Cleanup does not depend on current route or backend support.
	f.policies = `not-json`
	if err := m.Apply(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(f.rules) != 0 {
		t.Fatal(f.rules)
	}
}

func TestUnsafeJournalCannotMutate(t *testing.T) {
	m, f := manager(t)
	if err := os.WriteFile(m.StateFile, []byte(`{"version":1,"entries":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if m.Apply(context.Background(), []spec.WireGuardLink{link()}) == nil {
		t.Fatal("public journal accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
}

func TestLiveKernelMismatchNeverReportsSyncedOrRewrites(t *testing.T) {
	for _, mode := range []string{"missing", "duplicate", "extra-selector"} {
		t.Run(mode, func(t *testing.T) {
			m, f := manager(t)
			if err := m.Apply(context.Background(), []spec.WireGuardLink{link()}); err != nil {
				t.Fatal(err)
			}
			f.liveMode = mode
			before := f.mutations
			if m.Refresh(context.Background()) == nil || m.Status().State != "error" {
				t.Fatal(m.Status())
			}
			if m.Apply(context.Background(), nil) == nil {
				t.Fatal("runtime mismatch allowed deletion")
			}
			if f.mutations != before {
				t.Fatal("runtime mismatch caused a rewrite")
			}
		})
	}
}

func TestUnchangedRefreshUsesOnePersistentAndOneLiveSnapshot(t *testing.T) {
	m, f := manager(t)
	links := []spec.WireGuardLink{}
	for i := 1; i <= 16; i++ {
		links = append(links, spec.WireGuardLink{Slot: i, Exit: true})
	}
	if err := m.Apply(context.Background(), links); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	persistent, live := 0, 0
	for _, call := range f.calls {
		if call == "ufw show added" {
			persistent++
		}
		if call == "iptables -w 2 -S" {
			live++
		}
	}
	if persistent != 1 || live != 1 {
		t.Fatalf("per-rule process regression: %v", f.calls)
	}
}

func TestLoggedAndUnknownUFWRulesNeverReplaced(t *testing.T) {
	for _, action := range []string{"allow log", "deny log", "deny log-all"} {
		t.Run(action, func(t *testing.T) {
			m, f := manager(t)
			manual := "ufw route " + action + " in on bwg1 out on wan0 proto udp from 10.10.0.5 to any comment 'operator'"
			f.rules = []string{manual}
			if m.Apply(context.Background(), []spec.WireGuardLink{link()}) == nil {
				t.Fatal("logged operator rule accepted")
			}
			if f.mutations != 0 || len(f.rules) != 1 || f.rules[0] != manual {
				t.Fatal("operator rule modified", f.rules)
			}
		})
	}
	m, f := manager(t)
	f.rules = []string{"ufw route allow in on bwg1 out on wan0 app Unknown"}
	if m.Apply(context.Background(), []spec.WireGuardLink{link()}) == nil || f.mutations != 0 {
		t.Fatal("unknown rule syntax was mutated")
	}
}

func TestLiveMultiportRangeNormalization(t *testing.T) {
	for _, port := range []struct{ flag, source, destination string }{{"--sports", "8000:9000", ""}, {"--dports", "", "8000:9000"}} {
		r, ok := parseLiveUFW("-A ufw-user-forward -s 10.10.0.5/32 -i bwg1 -o lan0 -p tcp -m multiport "+port.flag+" 8000:9000 -j ACCEPT", "ufw-user-forward")
		if !ok || r.SourcePort != port.source || r.DestinationPort != port.destination {
			t.Fatalf("%+v %v", r, ok)
		}
	}
	if _, ok := parseLiveUFW("-A ufw-user-forward -i bwg1 -o lan0 -p tcp -m multiport --dports 8000,9000 -j ACCEPT", "ufw-user-forward"); ok {
		t.Fatal("comma list mistaken for a single port range")
	}
}
