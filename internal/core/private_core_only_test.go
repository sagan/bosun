package core

import (
	"net/netip"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestCoreOnlyComplement(t *testing.T) {
	ib := spec.Inbound{Tag: "grant", PrivateAccess: &spec.PrivateAccess{Mode: "custom", Enforcement: "core_only", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2/32", Protocol: "tcp", PortStart: 443}, {CIDR: "fd42::/64", PortStart: 8000, PortEnd: 8005}}}}
	rules, err := CoreOnlyRejects([]spec.Inbound{ib})
	if err != nil {
		t.Fatal(err)
	}
	denied := func(ip, network string, port int) bool {
		for _, v := range rules {
			r := v.(map[string]any)
			if r["network"].([]string)[0] != network {
				continue
			}
			lo, hi, _ := spec.ParsePortMatch(r["port_range"].([]string)[0])
			if port < lo || port > hi {
				continue
			}
			for _, cidr := range r["ip_cidr"].([]string) {
				if netip.MustParsePrefix(cidr).Contains(netip.MustParseAddr(ip)) {
					return true
				}
			}
		}
		return false
	}
	for _, tc := range []struct {
		ip, network string
		port        int
		blocked     bool
	}{{"10.10.0.2", "tcp", 443, false}, {"10.10.0.2", "udp", 443, true}, {"10.10.0.2", "tcp", 444, true}, {"10.10.0.3", "tcp", 443, true}, {"127.0.0.1", "tcp", 443, true}, {"169.254.169.254", "tcp", 443, true}, {"fd42::2", "udp", 8001, false}, {"fd43::2", "udp", 8001, true}, {"fd00:ec2::254", "tcp", 443, true}} {
		if denied(tc.ip, tc.network, tc.port) != tc.blocked {
			t.Fatalf("incorrect complement: %+v", tc)
		}
	}
}
