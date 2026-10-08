package spec

import (
	"fmt"
	"net/netip"
)

// EgressUpstream permits a core socket to reach an operator-approved upstream.
// It does not change the destination rules applied to subscriber traffic.
// Use a literal address/prefix so DNS changes cannot widen the exception.
type EgressUpstream struct {
	CIDR     string `json:"cidr" yaml:"cidr"`
	Protocol string `json:"protocol" yaml:"protocol"`
	Port     int    `json:"port" yaml:"port"`
}

func (u EgressUpstream) Prefix() (netip.Prefix, error) {
	if a, err := netip.ParseAddr(u.CIDR); err == nil && a.Zone() == "" {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(u.CIDR)
	if err != nil || p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("upstream must use a literal IP or unmapped CIDR")
	}
	return p.Masked(), nil
}

func ValidateEgressUpstreams(list []EgressUpstream) error {
	if len(list) > 64 {
		return fmt.Errorf("at most 64 upstream exceptions are allowed")
	}
	for i, u := range list {
		if _, err := u.Prefix(); err != nil {
			return fmt.Errorf("upstream %d: %w", i+1, err)
		}
		if u.Protocol != "tcp" && u.Protocol != "udp" {
			return fmt.Errorf("upstream %d: protocol must be tcp or udp", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("upstream %d: port must be 1-65535", i+1)
		}
	}
	return nil
}

// PrivateRanges is the default subscriber destination deny policy, shared by
// core renderers and nft. Kept under its historical name for API compatibility.
// Explicit special-use ranges, not all IANA assignments or unallocated space.
// Sources: IANA IPv4/IPv6 Special-Purpose registries (2026-10-07), RFC 1112/4291.
// The 192.0.0.0/24 split retains globally reachable .9 and .10 anycast. Global
// NAT64, Teredo, 6to4 and other globally reachable special allocations remain.
var PrivateRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/29", "192.0.0.8/32", "192.0.0.11/32", "192.0.0.12/30", "192.0.0.16/28", "192.0.0.32/27", "192.0.0.64/26", "192.0.0.128/25",
	"192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "100:0:0:1::/64", "2001:2::/48", "2001:10::/28", "2001:db8::/32", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
}

func BlockedDestinationRanges(ipv6 bool) []string {
	var out []string
	for _, c := range PrivateRanges {
		p := netip.MustParsePrefix(c)
		if p.Addr().Is6() == ipv6 {
			out = append(out, c)
		}
	}
	return out
}
