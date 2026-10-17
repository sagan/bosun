package xray

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

func TestWireGuardRoutesKeepBillingAndBoundSockets(t *testing.T) {
	priv, _, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	_, peer, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	grant := &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.20.0.0/24", Protocol: "tcp", PortStart: 443}, {CIDR: "fd20::/64", Protocol: "tcp", PortStart: 443}}}
	link := spec.WireGuardLink{Slot: 1, PrivateKey: priv, PeerKey: peer, ListenPort: 51820, MTU: 1380, PrivateAccess: grant}
	ib := spec.Inbound{Tag: "paid", Core: "xray", Protocol: spec.VLESS, Port: 18443, WireGuardSlot: 1, PrivateAccess: grant}
	u := spec.User{ID: 1, Name: "customer", UUID: "00000000-0000-4000-8000-000000000001", SpeedLimitMbps: 2}
	n := spec.Node{WireGuardLinks: []spec.WireGuardLink{link}, Inbounds: []spec.Inbound{ib}, Routes: []spec.RouteRule{{Action: "direct"}}, AuditRules: []spec.AuditRule{{ID: 1, Match: []string{"ip:10.20.0.3/32"}, Action: "block"}}}
	b, st, err := render(&n, n.Inbounds, []spec.User{u}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), priv) || strings.Contains(string(b), peer) {
		t.Fatal("transport credentials leaked into proxy config")
	}
	if len(st.users["paid"]) != 1 || st.users["paid"][u.Name].ID != u.ID {
		t.Fatal("billing identity changed")
	}
	cfg := decode(t, b)
	client := cfg["inbounds"].([]any)[0].(m)["settings"].(m)["clients"].([]any)[0].(m)
	if client["email"] != spec.InboundUser(u.Name, ib.Tag) {
		t.Fatal("inbound accounting email changed")
	}
	outs := map[string]m{}
	for _, raw := range cfg["outbounds"].([]any) {
		o := raw.(m)
		outs[o["tag"].(string)] = o
	}
	rules := cfg["routing"].(m)["rules"].([]any)
	for _, tc := range []struct {
		ip, proto string
		port      int
		blocked   bool
	}{{"10.20.0.2", "tcp", 443, false}, {"fd20::2", "tcp", 443, false}, {"10.20.0.2", "udp", 443, true}, {"10.20.0.2", "tcp", 80, true}, {"10.20.0.3", "tcp", 443, true}, {"100.100.100.200", "tcp", 443, true}, {"127.0.0.1", "tcp", 443, true}} {
		tag := firstWireGuardRule(t, rules, ib.Tag, spec.InboundUser(u.Name, ib.Tag), tc.ip, tc.proto, tc.port)
		if tc.blocked {
			if tag != "block" {
				t.Fatalf("unauthorized %s:%d routed to %s", tc.ip, tc.port, tag)
			}
			continue
		}
		o := outs[tag]
		v6 := netip.MustParseAddr(tc.ip).Is6()
		if o["protocol"] != "freedom" || o["sendThrough"] != link.Address(false, v6) {
			t.Fatalf("managed destination escaped tunnel: %s -> %v", tc.ip, o)
		}
		mark := int64(o["streamSettings"].(m)["sockopt"].(m)["mark"].(float64))
		grants, err := n.PrivateGrants([]spec.User{u})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, g := range grants {
			found = found || (g.UserID == u.ID && g.Mark == mark)
		}
		if !found {
			t.Fatal("private socket lost user shaping identity")
		}
	}
	// The renderer's selected slice is independently checked, including when
	// the caller supplied no inbounds in the node envelope.
	envelope := n
	envelope.Inbounds = nil
	mismatched := ib
	mismatched.PrivateAccess = nil
	if _, _, err := render(&envelope, []spec.Inbound{mismatched}, []spec.User{u}, renderOptions{}); err == nil {
		t.Fatal("selected inbound bypassed link grants")
	}
	// Transport changes must restart sockets instead of hot-updating users.
	n.WireGuardLinks[0].Slot = 2
	n.Inbounds[0].WireGuardSlot = 2
	_, st2, err := render(&n, n.Inbounds, []spec.User{u}, renderOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if st.inboundsKey == st2.inboundsKey {
		t.Fatal("link change did not invalidate socket configuration")
	}
	for _, patch := range []string{`{"routing":null}`, `{"inbounds":[]}`, `{"outbounds":[]}`, `{"dns":{}}`} {
		n.Overrides = map[string]json.RawMessage{"xray": json.RawMessage(patch)}
		if _, _, err := render(&n, n.Inbounds, []spec.User{u}, renderOptions{}); err == nil {
			t.Fatal("override bypass accepted")
		}
	}
	n.Overrides = nil
	n.WireGuardLinks = nil
	if _, _, err := render(&n, n.Inbounds, []spec.User{u}, renderOptions{}); err == nil {
		t.Fatal("missing tunnel fell back to direct")
	}
}

// Evaluate only the selectors exercised by this test; reject new selector
// types rather than accidentally treating an unimplemented matcher as true.
func firstWireGuardRule(t *testing.T, rules []any, inbound, user, ip, network string, port int) string {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	for _, raw := range rules {
		r := raw.(m)
		match := true
		for key, val := range r {
			switch key {
			case "type", "outboundTag":
			case "inboundTag", "user":
				want := inbound
				if key == "user" {
					want = user
				}
				found := false
				for _, v := range val.([]any) {
					found = found || v == want
				}
				match = match && found
			case "ip":
				found := false
				for _, v := range val.([]any) {
					p, err := netip.ParsePrefix(v.(string))
					if err != nil {
						t.Fatal(err)
					}
					found = found || p.Contains(addr)
				}
				match = match && found
			case "network":
				match = match && strings.Contains(val.(string), network)
			case "port":
				found := false
				for _, part := range strings.Split(val.(string), ",") {
					bounds := strings.Split(part, "-")
					lo, _ := strconv.Atoi(bounds[0])
					hi := lo
					if len(bounds) > 1 {
						hi, _ = strconv.Atoi(bounds[1])
					}
					found = found || (port >= lo && port <= hi)
				}
				match = match && found
			default:
				t.Fatalf("unhandled routing selector %s", key)
			}
		}
		if match {
			return r["outboundTag"].(string)
		}
	}
	t.Fatal("managed flow has no explicit route")
	return ""
}
