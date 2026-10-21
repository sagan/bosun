package core

import (
	"fmt"
	"net/netip"
	"slices"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// CoreOnlyRejects rejects ANY resolved address outside the inbound's grant
// before ordinary routing runs. A positive CIDR match alone is unsafe:
// a DNS answer can contain both an allowed and an unauthorized private IP.
// Complements are compiled independently for each transport and port segment.
func CoreOnlyRejects(inbounds []spec.Inbound) ([]any, error) {
	var out []any
	size := 0
	for _, ib := range inbounds {
		if !ib.PrivateAccess.CoreOnly() {
			continue
		}
		tag := ib.Tag
		if ib.ShadowTLS != nil {
			tag = spec.ShadowTLSTag(tag)
		}
		access := ib.PrivateAccess.EffectiveRules()
		for _, network := range []string{"tcp", "udp"} {
			boundaries := []int{1, 65536}
			for _, r := range access {
				if r.Protocol == "" || r.Protocol == network {
					if r.PortStart > 0 {
						boundaries = append(boundaries, r.PortStart, r.PortEnd+1)
					}
				}
			}
			slices.Sort(boundaries)
			boundaries = slices.Compact(boundaries)
			for i := 0; i+1 < len(boundaries); i++ {
				lo, hi := boundaries[i], boundaries[i+1]-1
				var denied []netip.Prefix
				for _, cidr := range spec.PrivateRanges {
					denied = append(denied, netip.MustParsePrefix(cidr))
				}
				for _, r := range access {
					if r.Protocol != "" && r.Protocol != network || r.PortStart != 0 && (lo < r.PortStart || hi > r.PortEnd) {
						continue
					}
					grant := netip.MustParsePrefix(r.CIDR)
					var remaining []netip.Prefix
					for _, p := range denied {
						remaining = append(remaining, subtractPrefix(p, grant)...)
					}
					denied = remaining
				}
				var cidrs []string
				for _, p := range denied {
					cidrs = append(cidrs, p.String())
				}
				cidrs = append(cidrs, spec.PrivateAccessProtectedRanges...)
				size += len(cidrs)
				if size > 16384 {
					return nil, fmt.Errorf("core-only private access exceeds compiled address limit")
				}
				out = append(out, map[string]any{"inbound": []string{tag}, "network": []string{network}, "port_range": []string{fmt.Sprintf("%d:%d", lo, hi)}, "ip_cidr": cidrs, "action": "reject"})
			}
		}
	}
	return out, nil
}

func subtractPrefix(base, remove netip.Prefix) []netip.Prefix {
	base = base.Masked()
	remove = remove.Masked()
	if base.Addr().BitLen() != remove.Addr().BitLen() || !base.Overlaps(remove) {
		return []netip.Prefix{base}
	}
	if remove.Bits() <= base.Bits() {
		return nil
	}
	bytes := base.Addr().AsSlice()
	bit := base.Bits()
	bytes[bit/8] |= 1 << uint(7-bit%8)
	next, _ := netip.AddrFromSlice(bytes)
	left := netip.PrefixFrom(base.Addr(), bit+1)
	right := netip.PrefixFrom(next, bit+1)
	return append(subtractPrefix(left, remove), subtractPrefix(right, remove)...)
}
