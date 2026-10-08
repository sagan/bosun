package spec

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// PrivateAccess grants subscriber destinations on one inbound. It never grants
// control-plane/upstream access. An explicit off object also works with clients
// which preserve omitted fields during updates.
type PrivateAccess struct {
	Mode  string              `json:"mode"` // off, internal (RFC1918 + ULA), custom
	Rules []PrivateAccessRule `json:"rules,omitempty"`
}

type PrivateAccessRule struct {
	CIDR      string `json:"cidr"`
	Protocol  string `json:"protocol,omitempty"`   // empty = TCP and UDP
	PortStart int    `json:"port_start,omitempty"` // both zero = all ports
	PortEnd   int    `json:"port_end,omitempty"`   // zero = PortStart
}

// Known metadata endpoints inside otherwise eligible address spaces.
var PrivateAccessProtectedRanges = []string{"100.100.100.200/32", "fd00:ec2::254/128"}

var internalAccessRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

func (p *PrivateAccess) Enabled() bool { return p != nil && p.Mode != "off" }

func (r PrivateAccessRule) Prefix() (netip.Prefix, error) {
	p, err := netip.ParsePrefix(r.CIDR)
	if err != nil {
		a, e := netip.ParseAddr(r.CIDR)
		if e != nil || a.Zone() != "" || a.Is4In6() {
			return netip.Prefix{}, fmt.Errorf("private access requires an IP or CIDR")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 is not allowed")
	}
	return p.Masked(), nil
}

func (p *PrivateAccess) Validate() error {
	if p == nil {
		return nil
	}
	switch p.Mode {
	case "off", "internal":
		if len(p.Rules) != 0 {
			return fmt.Errorf("only custom private access accepts rules")
		}
	case "custom":
		if len(p.Rules) < 1 || len(p.Rules) > 64 {
			return fmt.Errorf("private access needs 1-64 explicit rules")
		}
	default:
		return fmt.Errorf("private access mode must be off, internal or custom")
	}
	for _, r := range p.Rules {
		prefix, err := r.Prefix()
		if err != nil {
			return err
		}
		allowed := false
		for _, cidr := range append(append([]string{}, internalAccessRanges...), "100.64.0.0/10") {
			parent := netip.MustParsePrefix(cidr)
			allowed = allowed || (parent.Contains(prefix.Addr()) && parent.Bits() <= prefix.Bits())
		}
		if !allowed {
			return fmt.Errorf("private access accepts RFC1918, IPv6 ULA or explicit CGNAT ranges only; loopback, link-local and metadata stay protected")
		}
		for _, cidr := range PrivateAccessProtectedRanges {
			protected := netip.MustParsePrefix(cidr)
			if protected.Contains(prefix.Addr()) && protected.Bits() <= prefix.Bits() {
				return fmt.Errorf("metadata endpoints cannot be granted private access")
			}
		}
		if r.Protocol != "" && r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("private access protocol must be tcp, udp or empty")
		}
		if r.PortStart < 0 || r.PortStart > 65535 || r.PortEnd < 0 || r.PortEnd > 65535 || (r.PortEnd != 0 && (r.PortStart == 0 || r.PortEnd < r.PortStart)) {
			return fmt.Errorf("private access ports must be 1-65535 in ascending order, or both zero")
		}
	}
	return nil
}

func (p *PrivateAccess) EffectiveRules() []PrivateAccessRule {
	if !p.Enabled() {
		return nil
	}
	if p.Mode == "internal" {
		out := make([]PrivateAccessRule, 0, len(internalAccessRanges))
		for _, c := range internalAccessRanges {
			out = append(out, PrivateAccessRule{CIDR: c})
		}
		return out
	}
	out := append([]PrivateAccessRule(nil), p.Rules...)
	for i := range out {
		if prefix, err := out[i].Prefix(); err == nil {
			out[i].CIDR = prefix.String()
		}
		if out[i].PortEnd == 0 {
			out[i].PortEnd = out[i].PortStart
		}
	}
	return out
}

// PrivateGrant is a compiled socket identity, not a stored/wire configuration.
// A limited user's additional marks map to their existing tc class.
type PrivateGrant struct {
	Inbound  string
	UserID   int64
	UserName string
	Mark     int64
	Rules    []PrivateAccessRule
}

func (n *Node) HasPrivateAccess() bool {
	for _, ib := range n.Inbounds {
		if ib.PrivateAccess.Enabled() {
			return true
		}
	}
	for _, c := range n.ReverseClients {
		if c.PrivateAccess.Enabled() {
			return true
		}
	}
	return false
}

// ValidatePrivateAccessNode refuses combinations whose final dial socket cannot
// reliably carry the scope. In particular a proxy/detour may resolve at an
// uncontrolled remote exit, and raw overrides can erase managed routes/marks.
func (n *Node) ValidatePrivateAccessNode() error {
	for _, ib := range n.Inbounds {
		if err := ib.PrivateAccess.Validate(); err != nil {
			return err
		}
	}
	for _, c := range n.ReverseClients {
		if err := c.PrivateAccess.Validate(); err != nil {
			return err
		}
	}
	if !n.HasPrivateAccess() {
		return nil
	}
	for _, ib := range n.Inbounds {
		if ib.Tag == "bosun-private-dns" {
			return fmt.Errorf("bosun-private-dns is reserved while private access is enabled")
		}
	}
	if n.AllowPrivateDest || len(n.PrivateDestAllow) > 0 {
		return fmt.Errorf("per-inbound private access conflicts with global private destination permissions")
	}
	for _, raw := range n.Overrides {
		var v map[string]any
		if len(raw) != 0 && json.Unmarshal(raw, &v) != nil {
			return fmt.Errorf("invalid core override")
		}
		for _, key := range []string{"routing", "route", "outbounds", "endpoints", "inbounds", "policy", "dns"} {
			if _, ok := v[key]; ok {
				return fmt.Errorf("private access cannot override %s", key)
			}
		}
	}
	for _, o := range n.Outbounds {
		if o.Remote != nil || o.WARP != nil || o.Balancer != nil || o.ProxyTag != "" || (o.Protocol != "direct" && o.Protocol != "freedom") {
			return fmt.Errorf("private access currently requires direct exits (OS WireGuard routes are supported); proxy chains, WARP and balancers are unsupported")
		}
		// Keep only fields which cannot redirect the target or replace a mark.
		for k := range o.Settings {
			switch k {
			case "domain_strategy", "domainStrategy", "inet4_bind_address", "inet6_bind_address", "bind_interface":
			default:
				return fmt.Errorf("private access cannot use outbound setting %s", k)
			}
		}
		if strings.HasPrefix(o.Tag, "private-") {
			return fmt.Errorf("private- outbound tags are reserved")
		}
	}
	// GeoIP cannot be intersected with a literal allowlist in Xray's flat
	// rule format. Do not weaken it by silently dropping one condition.
	for _, r := range n.Routes {
		for _, m := range r.Match {
			if strings.HasPrefix(m, "geoip:") {
				return fmt.Errorf("private access does not support geoip route matches; use explicit CIDRs")
			}
		}
	}
	return nil
}

// PrivateGrants is deterministic across core renderers and firewall/shaper.
// Marks are collision-checked against every legacy speed mark; no assumptions
// about the magnitude of user IDs or spare bits in SpeedMark are made.
func (n *Node) PrivateGrants(users []User) ([]PrivateGrant, error) {
	if err := n.ValidatePrivateAccessNode(); err != nil {
		return nil, err
	}
	var grants []PrivateGrant
	for _, ib := range n.Inbounds {
		if !ib.PrivateAccess.Enabled() || ib.Reverse != nil {
			continue
		} // A must always tunnel to B
		tag := ib.Tag
		if ib.ShadowTLS != nil {
			tag = ShadowTLSTag(tag)
		}
		for _, u := range ib.EffectiveUsers(users) {
			if n.EffectiveSpeedLimit(u) > 0 {
				grants = append(grants, PrivateGrant{Inbound: tag, UserID: u.ID, UserName: privateAuthName(ib, u), Rules: ib.PrivateAccess.EffectiveRules()})
			}
		}
		grants = append(grants, PrivateGrant{Inbound: tag, Rules: ib.PrivateAccess.EffectiveRules()})
	}
	for _, c := range n.ReverseClients {
		if c.PrivateAccess.Enabled() {
			grants = append(grants, PrivateGrant{Inbound: ReverseTag(c.ID) + "-exit", Rules: c.PrivateAccess.EffectiveRules()})
		}
	}
	if len(grants) > 4096 {
		return nil, fmt.Errorf("private access exceeds 4096 socket identities")
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Inbound != grants[j].Inbound {
			return grants[i].Inbound < grants[j].Inbound
		}
		return grants[i].UserID > grants[j].UserID
	})
	used := map[int64]bool{}
	for _, u := range users {
		used[SpeedMark(u.ID)] = true
	}
	for i := range grants {
		b, _ := json.Marshal(grants[i])
		h := sha256.Sum256(b)
		mark := int64(binary.BigEndian.Uint32(h[:4])&0x3fffffff) + 0x40000000
		for used[mark] {
			mark = 0x40000000 + ((mark + 1) & 0x3fffffff)
		}
		used[mark] = true
		grants[i].Mark = mark
	}
	return grants, nil
}

func privateAuthName(ib Inbound, u User) string {
	switch ib.Protocol {
	case SOCKS, HTTP, Naive:
		return u.Name
	}
	return InboundUser(u.Name, ib.Tag)
}
