package egressguard

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func validatePrivateGrants(uid int, opt Options) error {
	if len(opt.PrivateGrants) == 0 {
		return nil
	}
	if uid <= 0 || opt.Disabled || len(opt.Allow) > 0 {
		return fmt.Errorf("private access requires a non-root core account and enabled egress guard without global CIDR exceptions")
	}
	seen := map[int64]bool{}
	for _, g := range opt.PrivateGrants {
		if g.Mark <= 0 || g.Mark > 0x7fffffff || seen[g.Mark] {
			return fmt.Errorf("invalid private access socket identity")
		}
		seen[g.Mark] = true
		if err := (&spec.PrivateAccess{Mode: "custom", Rules: g.Rules}).Validate(); err != nil {
			return err
		}
	}
	return nil
}

func writePrivateGrants(b *strings.Builder, uid int, grants []spec.PrivateGrant) {
	// Invalid inputs must never become an accept rule, even via Script in tests.
	if validatePrivateGrants(uid, Options{PrivateGrants: grants}) != nil {
		return
	}
	for _, cidr := range spec.PrivateAccessProtectedRanges {
		p := netip.MustParsePrefix(cidr)
		family := "ip"
		if p.Addr().Is6() {
			family = "ip6"
		}
		if len(grants) > 0 {
			fmt.Fprintf(b, "    meta skuid %d ct direction original %s daddr %s drop\n", uid, family, p)
		}
	}
	for _, g := range grants {
		for _, r := range g.Rules {
			prefix, _ := r.Prefix()
			family := "ip"
			if prefix.Addr().Is6() {
				family = "ip6"
			}
			protocols := []string{"tcp", "udp"}
			if r.Protocol != "" {
				protocols = []string{r.Protocol}
			}
			for _, proto := range protocols {
				port := ""
				if r.PortStart > 0 {
					end := r.PortEnd
					if end == 0 {
						end = r.PortStart
					}
					port = fmt.Sprintf(" %s dport %d-%d", proto, r.PortStart, end)
				}
				fmt.Fprintf(b, "    meta skuid %d meta mark %d ct direction original %s daddr %s meta l4proto %s%s accept\n", uid, g.Mark, family, prefix, proto, port)
			}
		}
		// A marked subscriber socket cannot borrow an upstream/DNS exception.
		for _, v6 := range []bool{false, true} {
			family := "ip"
			if v6 {
				family = "ip6"
			}
			fmt.Fprintf(b, "    meta skuid %d meta mark %d ct direction original %s daddr { %s } drop\n", uid, g.Mark, family, strings.Join(spec.BlockedDestinationRanges(v6), ", "))
		}
	}
}
