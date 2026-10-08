package spec

import (
	"net/netip"
	"testing"
)

func TestDestinationPolicy(t *testing.T) {
	blocked := func(ip string) bool {
		a := netip.MustParseAddr(ip).Unmap()
		for _, c := range PrivateRanges {
			if netip.MustParsePrefix(c).Contains(a) {
				return true
			}
		}
		return false
	}
	for _, ip := range []string{"0.0.0.1", "10.10.0.2", "127.0.0.1", "169.254.169.254", "192.0.0.8", "192.0.0.11", "192.0.0.170", "192.0.2.10", "192.88.99.2", "198.18.0.1", "198.51.100.20", "203.0.113.30", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:10.10.0.2", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1", "3fff::1", "2001:2::1", "100::1", "64:ff9b:1::1"} {
		if !blocked(ip) {
			t.Errorf("not blocked: %s", ip)
		}
	}
	for _, ip := range []string{"192.0.0.9", "192.0.0.10", "192.31.196.1", "192.52.193.1", "192.175.48.1", "64:ff9b::808:808", "2001:1::1", "2001:1::2", "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1", "2620:4f:8000::1"} {
		if blocked(ip) {
			t.Errorf("global exception blocked: %s", ip)
		}
	}
}
func TestEgressUpstreamValidationAndUserIsolation(t *testing.T) {
	good := EgressUpstream{CIDR: "10.10.0.2", Protocol: "tcp", Port: 1080}
	for _, u := range []EgressUpstream{good, {CIDR: "2001:db8::10/64", Protocol: "udp", Port: 53}} {
		if err := ValidateEgressUpstreams([]EgressUpstream{u}); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []EgressUpstream{{CIDR: "example.com", Protocol: "tcp", Port: 1080}, {CIDR: "10.10.0.2; accept", Protocol: "tcp", Port: 1080}, {CIDR: "10.10.0.2", Protocol: "tcp accept", Port: 1080}, {CIDR: "10.10.0.2", Protocol: "tcp", Port: 0}, {CIDR: "::ffff:10.10.0.2/120", Protocol: "udp", Port: 53}, {CIDR: "fe80::1%eth0", Protocol: "tcp", Port: 443}} {
		if ValidateEgressUpstreams([]EgressUpstream{u}) == nil {
			t.Fatalf("invalid exception accepted: %+v", u)
		}
	}
	n := Node{EgressUpstreams: []EgressUpstream{good}}
	for _, rule := range n.PrivateDestRules() {
		if rule.Action != "block" {
			t.Fatal("upstream exception leaked into subscriber permission", rule)
		}
	}
}
