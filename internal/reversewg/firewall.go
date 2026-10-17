package reversewg

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

const firewallTable = "bosun_reversewg"

// Firewall compiles a complete owned table. Callers replace it in one nft
// transaction. No established-flow shortcut may precede the destination ACL:
// otherwise removing a grant would leave existing connections authorized.
func Firewall(configs []Config) (string, error) {
	cs := append([]Config(nil), configs...)
	sort.Slice(cs, func(i, j int) bool { return cs[i].Slot < cs[j].Slot })
	seen := map[int]bool{}
	var input, output, forward, nat, related strings.Builder
	for _, c := range cs {
		if err := c.Validate(); err != nil {
			return "", err
		}
		if seen[c.Slot] {
			return "", fmt.Errorf("duplicate reverse WireGuard slot")
		}
		seen[c.Slot] = true
		dev := c.Interface()
		for _, v6 := range []bool{false, true} {
			family, icmp := "ip", "icmp type destination-unreachable icmp code frag-needed"
			if v6 {
				family, icmp = "ip6", "icmpv6 type packet-too-big"
			}
			chain := fmt.Sprintf("pmtu_%d_%s", c.Slot, family)
			writePMTUChain(&related, c, v6, chain)
			// Only conntrack-associated MTU errors about this link's own
			// authorized TCP/UDP sockets may enter A. Echo and redirects do not.
			match := fmt.Sprintf("%s daddr %s %s ct state related ct direction reply ct original %s saddr %s jump %s\n", family, c.Address(false, v6), icmp, family, c.Address(false, v6), chain)
			if c.Exit {
				fmt.Fprintf(&forward, "oifname %q iifname != \"bwg*\" %s", dev, match)
				fmt.Fprintf(&output, "oifname %q %s", dev, match)
			} else {
				fmt.Fprintf(&input, "iifname %q %s", dev, match)
			}
		}
		if !c.Exit {
			// Replies to locally originated sockets are allowed, unsolicited
			// packets and all forwarded traffic on A are not.

			fmt.Fprintf(&input, "iifname %q ct state established ct direction reply accept\niifname %q drop\n", dev, dev)
			fmt.Fprintf(&forward, "iifname %q drop\noifname %q drop\n", dev, dev)
			for _, v6 := range []bool{false, true} {
				family := "ip"
				if v6 {
					family = "ip6"
				}
				// Prevent fallback even if a route/rule/interface disappears.
				fmt.Fprintf(&output, "%s saddr %s oifname != %q counter drop\n", family, c.Address(false, v6), dev)
				fmt.Fprintf(&output, "oifname %q %s saddr != %s drop\n", dev, family, c.Address(false, v6))
			}
			continue
		}
		fmt.Fprintf(&input, "iifname %q counter drop\n", dev)
		// A link must never become a bridge into a second managed link.
		fmt.Fprintf(&forward, "iifname %q oifname \"bwg*\" drop\n", dev)
		for _, v6 := range []bool{false, true} {
			family := "ip"
			if v6 {
				family = "ip6"
			}
			src := c.Address(false, v6)
			fmt.Fprintf(&forward, "%s daddr %s oifname != %q counter drop\n", family, src, dev)
			fmt.Fprintf(&forward, "iifname %q %s saddr != %s drop\n", dev, family, src)
			writeACL(&forward, c, v6, false)
			writeACL(&forward, c, v6, true)
			fmt.Fprintf(&nat, "iifname %q %s saddr %s masquerade\n", dev, family, src)
		}
		fmt.Fprintf(&forward, "iifname %q meta l4proto { tcp, udp } ct direction original accept\niifname %q drop\n", dev, dev)
		fmt.Fprintf(&forward, "oifname %q meta l4proto { tcp, udp } ct state established ct direction reply accept\noifname %q drop\n", dev, dev)
		// B cannot originate traffic into A, including its local processes.
		fmt.Fprintf(&output, "oifname %q drop\n", dev)
	}
	return fmt.Sprintf("table inet %s {\n%schain input { type filter hook input priority -10; policy accept;\n%s}\nchain output { type filter hook output priority -10; policy accept;\n%s}\nchain forward { type filter hook forward priority -10; policy accept;\n%s}\nchain postrouting { type nat hook postrouting priority srcnat; policy accept;\n%s}\n}\n", firewallTable, related.String(), input.String(), output.String(), forward.String(), nat.String()), nil
}

// The reply path checks the source address/port against the same grant. This
// stops ongoing downloads as well as uploads when a private grant is revoked.
func writeACL(b *strings.Builder, c Config, v6, reply bool) {
	family := "ip"
	if v6 {
		family = "ip6"
	}
	iface, addr, port, direction := "iifname", "daddr", "dport", "original"
	state := ""
	if reply {
		iface, addr, port, direction = "oifname", "saddr", "sport", "reply"
		state = "ct state established "
	}
	prefix := fmt.Sprintf("%s %q", iface, c.Interface())
	for _, cidr := range spec.PrivateAccessProtectedRanges {
		if netip.MustParsePrefix(cidr).Addr().Is6() == v6 {
			fmt.Fprintf(b, "%s %s %s %s drop\n", prefix, family, addr, cidr)
		}
	}
	for _, r := range c.PrivateAccess.EffectiveRules() {
		p, _ := r.Prefix()
		if p.Addr().Is6() != v6 {
			continue
		}
		protos := []string{r.Protocol}
		if r.Protocol == "" {
			protos = []string{"tcp", "udp"}
		}
		for _, proto := range protos {
			fmt.Fprintf(b, "%s %s %s %s meta l4proto %s", prefix, family, addr, p.String(), proto)
			if r.PortStart > 0 {
				fmt.Fprintf(b, " %s %s %d-%d", proto, port, r.PortStart, r.PortEnd)
			}
			fmt.Fprintf(b, " %sct direction %s accept\n", state, direction)
		}
	}
	fmt.Fprintf(b, "%s %s %s { %s } drop\n", prefix, family, addr, strings.Join(spec.BlockedDestinationRanges(v6), ", "))
}

// Check the embedded flow tuple, not the router's ICMP source address. Related
// errors may originate at a private router even for a public destination, but
// must stop passing as soon as that flow's destination grant is revoked.
func writePMTUChain(b *strings.Builder, c Config, v6 bool, chain string) {
	family := "ip"
	if v6 {
		family = "ip6"
	}
	fmt.Fprintf(b, "chain %s {\n", chain)
	for _, cidr := range spec.PrivateAccessProtectedRanges {
		if netip.MustParsePrefix(cidr).Addr().Is6() == v6 {
			fmt.Fprintf(b, "ct original %s daddr %s drop\n", family, cidr)
		}
	}
	for _, r := range c.PrivateAccess.EffectiveRules() {
		p, _ := r.Prefix()
		if p.Addr().Is6() != v6 {
			continue
		}
		protos := []string{r.Protocol}
		if r.Protocol == "" {
			protos = []string{"tcp", "udp"}
		}
		for _, proto := range protos {
			fmt.Fprintf(b, "ct original %s daddr %s ct original protocol %s", family, p.String(), proto)
			if r.PortStart > 0 {
				fmt.Fprintf(b, " ct original proto-dst %d-%d", r.PortStart, r.PortEnd)
			}
			b.WriteString(" counter accept\n")
		}
	}
	fmt.Fprintf(b, "ct original %s daddr { %s } drop\nct original protocol { tcp, udp } counter accept\ndrop\n}\n", family, strings.Join(spec.BlockedDestinationRanges(v6), ", "))
}
