package spec

import (
	"reflect"
	"testing"
)

func TestPrivateAccessValidation(t *testing.T) {
	for _, p := range []*PrivateAccess{nil, {Mode: "off"}, {Mode: "internal"}, {Mode: "custom", Rules: []PrivateAccessRule{{CIDR: "10.10.0.2", Protocol: "tcp", PortStart: 443}, {CIDR: "fd00::/64"}, {CIDR: "100.64.0.1"}}}} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []PrivateAccessRule{{CIDR: "100.100.100.200"}, {CIDR: "fd00:ec2::254"}, {CIDR: "127.0.0.1"}, {CIDR: "169.254.169.254"}, {CIDR: "::1"}, {CIDR: "fe80::/10"}, {CIDR: "0.0.0.0/0"}, {CIDR: "::/0"}, {CIDR: "::ffff:10.10.0.2"}, {CIDR: "example.com"}, {CIDR: "10.10.0.2; accept"}, {CIDR: "10.10.0.2", Protocol: "all"}, {CIDR: "10.10.0.2", PortStart: 100, PortEnd: 90}, {CIDR: "10.10.0.2", PortEnd: 443}} {
		if (&PrivateAccess{Mode: "custom", Rules: []PrivateAccessRule{r}}).Validate() == nil {
			t.Fatalf("accepted unsafe rule %+v", r)
		}
	}
	for _, p := range []*PrivateAccess{{Mode: "custom"}, {Mode: ""}, {Mode: "internal", Rules: []PrivateAccessRule{{CIDR: "10.10.0.2"}}}} {
		if p.Validate() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}

func TestPrivateGrantsIsolatedStableAndSpeedCollision(t *testing.T) {
	p := &PrivateAccess{Mode: "custom", Rules: []PrivateAccessRule{{CIDR: "10.10.0.2", Protocol: "tcp", PortStart: 8080}}}
	n := &Node{Inbounds: []Inbound{{Tag: "allowed", Protocol: VLESS, PrivateAccess: p}, {Tag: "denied", Protocol: VLESS}}, UserSpeedLimitMbps: 2}
	users := []User{{ID: 1, Name: "one"}, {ID: 999999, Name: "two"}}
	grants, err := n.PrivateGrants(users)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 3 {
		t.Fatal(grants)
	}
	for _, g := range grants {
		if g.Inbound != "allowed" || g.Mark == SpeedMark(1) || g.Mark == SpeedMark(999999) {
			t.Fatal(g)
		}
	}
	other, _ := n.PrivateGrants([]User{users[1], users[0]})
	if !reflect.DeepEqual(grants, other) {
		t.Fatal("user ordering changes marks")
	}
	// Force a legacy large ID to occupy one hash candidate.
	users = append(users, User{ID: grants[0].Mark - 0x10000, Name: "collision"})
	changed, err := n.PrivateGrants(users)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range changed {
		for _, u := range users {
			if g.Mark == SpeedMark(u.ID) {
				t.Fatal("mark collision")
			}
		}
	}
	n.Inbounds[0].ShadowTLS = &ShadowTLS{}
	changed, _ = n.PrivateGrants(users)
	if changed[0].Inbound != ShadowTLSTag("allowed") {
		t.Fatal("wrong ShadowTLS scope")
	}
	n.Inbounds[0].Reverse = &ReverseInbound{ID: "link"}
	n.ReverseClients = []ReverseClient{{ID: "link", PrivateAccess: p}}
	changed, _ = n.PrivateGrants(users)
	if len(changed) != 1 || changed[0].Inbound != ReverseTag("link")+"-exit" {
		t.Fatal("reverse permission must only mark exit B", changed)
	}
}

func TestPrivateCapabilityAndNodeConflicts(t *testing.T) {
	ib := Inbound{Protocol: Hysteria2, PrivateAccess: &PrivateAccess{Mode: "internal"}}
	if !CapabilitiesForCore("singbox").Supports(ib) || CapabilitiesForCore("hysteria").Supports(ib) {
		t.Fatal("unsupported adapter advertised")
	}
	old := CapabilitiesForCore("singbox")
	old.PrivateAccess = false
	if old.Supports(ib) {
		t.Fatal("old node accepted")
	}
	n := &Node{Inbounds: []Inbound{ib}, Outbounds: []Outbound{{Tag: "proxy", Protocol: "socks"}}}
	if n.ValidatePrivateAccessNode() == nil {
		t.Fatal("proxy accepted")
	}
	n.Outbounds = nil
	n.AllowPrivateDest = true
	if n.ValidatePrivateAccessNode() == nil {
		t.Fatal("global exception accepted")
	}
}

func TestPrivateAccessNotExportedInTemplates(t *testing.T) {
	ib := Inbound{Tag: "internal", Protocol: VLESS, PrivateAccess: &PrivateAccess{Mode: "internal"}}
	if InboundTemplate(ib).PrivateAccess != nil {
		t.Fatal("template exported destination permissions")
	}
	if !ib.PrivateAccess.Enabled() {
		t.Fatal("template changed source inbound")
	}
}

func TestAutomaticIntentDoesNotPersistRuntimeMode(t *testing.T) {
	p := &PrivateAccess{Mode: "internal", Enforcement: "auto"}
	n := &Node{Inbounds: []Inbound{{Tag: "auto", PrivateAccess: p}}}
	if _, e := n.ResolvePrivateAccessIntent(true); e == nil {
		t.Fatal("downgrade without consent")
	}
	dual, e := n.ResolvePrivateAccessIntent(false)
	if e != nil || dual.Inbounds[0].PrivateAccess.Enforcement != "dual" {
		t.Fatal(e)
	}
	p.AllowCoreOnly = true
	weaker, e := n.ResolvePrivateAccessIntent(true)
	if e != nil || !weaker.Inbounds[0].PrivateAccess.CoreOnly() {
		t.Fatal(e)
	}
	if n.Inbounds[0].PrivateAccess.Enforcement != "auto" {
		t.Fatal("stored intent mutated")
	}
	if _, e = n.PrivateGrants(nil); e == nil {
		t.Fatal("unresolved intent compiled")
	}
	dual, e = n.ResolvePrivateAccessIntent(false)
	if e != nil || dual.Inbounds[0].PrivateAccess.CoreOnly() {
		t.Fatal("guard re-enable left stale core-only mode", e)
	}
}

func TestCoreOnlySplitRoutingGate(t *testing.T) {
	p := &PrivateAccess{Mode: "internal", Enforcement: "auto", AllowCoreOnly: true}
	ib := Inbound{Tag: "in", Protocol: VLESS, Core: "singbox", PrivateAccess: p}
	n := &Node{Inbounds: []Inbound{ib}, Outbounds: []Outbound{{Tag: "warp", WARP: &WARP{FromNode: true}}, {Tag: "proxy", Protocol: "socks"}, {Tag: "pool", Balancer: &Balancer{Members: []string{"proxy"}}}}}
	if err := n.ValidatePrivateAccessNode(); err != nil {
		t.Fatal(err)
	}
	c := CapabilitiesForCore("singbox")
	c.PrivateAccessPolicy = &PrivateAccessPolicyCapabilities{Scoped: true, IndependentDNS: true}
	c.PrivateAccessReadiness = &PrivateAccessReadiness{EffectiveMode: "core_only"}
	candidates := []CoreCandidate{{Name: "singbox", Capabilities: c}}
	if n.ValidatePrivateAccessRouting(candidates) == nil {
		t.Fatal("old compiler allowed")
	}
	candidates[0].Capabilities.PrivateAccessPolicy.SplitRouting = true
	if err := n.ValidatePrivateAccessRouting(candidates); err != nil {
		t.Fatal(err)
	}
	resolved, err := n.ResolvePrivateAccessIntent(true)
	if err != nil {
		t.Fatal(err)
	}
	if err = resolved.ValidatePrivateAccessNode(); err != nil {
		t.Fatal(err)
	}
	dual, err := n.ResolvePrivateAccessIntent(false)
	if err != nil {
		t.Fatal(err)
	}
	if dual.ValidatePrivateAccessNode() == nil {
		t.Fatal("dual mode silently allowed remote exits")
	}
	candidates[0].Capabilities.CoreOnlyPrivateAccess = false
	if n.ValidatePrivateAccessRouting(candidates) == nil {
		t.Fatal("runtime gate bypassed")
	}
	resolved.Outbounds = []Outbound{{Tag: "escape", Protocol: "direct", Settings: map[string]any{"override_address": "127.0.0.1"}}}
	if resolved.ValidatePrivateAccessNode() == nil {
		t.Fatal("target rewriting bypasses authorization")
	}
}
