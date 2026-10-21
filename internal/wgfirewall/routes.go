package wgfirewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

var interfacePattern = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

type Rule struct {
	Slot            int    `json:"slot"`
	In              string `json:"in"`
	Out             string `json:"out"`
	Source          string `json:"source"`
	Destination     string `json:"destination"`
	Protocol        string `json:"protocol"`
	SourcePort      string `json:"source_port,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
}

func (r Rule) key() string {
	b, _ := json.Marshal(r)
	return string(b)
}

func (r Rule) args() []string {
	a := []string{"route", "allow", "in", "on", r.In, "out", "on", r.Out, "proto", r.Protocol, "from", r.Source}
	if r.SourcePort != "" {
		a = append(a, "port", r.SourcePort)
	}
	a = append(a, "to", r.Destination)
	if r.DestinationPort != "" {
		a = append(a, "port", r.DestinationPort)
	}
	return a
}

func validPort(p string) bool {
	if p == "" {
		return true
	}
	a := strings.Split(p, ":")
	if len(a) > 2 {
		return false
	}
	last := 0
	for _, v := range a {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 || n < last {
			return false
		}
		last = n
	}
	return true
}

func (r Rule) valid() bool {
	if r.Slot < 1 || r.Slot > 16383 || !interfacePattern.MatchString(r.In) || !interfacePattern.MatchString(r.Out) || (r.Protocol != "tcp" && r.Protocol != "udp") || !validPort(r.SourcePort) || !validPort(r.DestinationPort) {
		return false
	}
	c := spec.WireGuardLink{Slot: r.Slot}
	for _, v6 := range []bool{false, true} {
		a := c.Address(false, v6)
		other := r.Destination
		if r.In != c.Interface() || r.Source != a {
			if r.Out != c.Interface() || r.Destination != a {
				continue
			}
			other = r.Source
		}
		if other == "any" {
			return true
		}
		p, err := netip.ParsePrefix(other)
		if err == nil && p.Addr().Is6() == v6 && p == p.Masked() {
			return true
		}
	}
	return false
}

type route struct {
	Dst      string            `json:"dst"`
	Dev      string            `json:"dev"`
	Type     string            `json:"type"`
	Metric   int               `json:"metric"`
	Nexthops []json.RawMessage `json:"nexthops"`
}

func (m *Manager) routes(ctx context.Context, v6 bool) ([]route, error) {
	family := "-4"
	if v6 {
		family = "-6"
	}
	b, err := m.run(ctx, "ip", "-j", family, "route", "show", "table", "main")
	if err != nil {
		return nil, errors.New("route_query_failed")
	}
	var routes []route
	if json.Unmarshal(b, &routes) != nil {
		return nil, errors.New("route_output_invalid")
	}
	// A disabled address family may have no policy rules at all.
	if len(routes) == 0 {
		return routes, nil
	}
	b, err = m.run(ctx, "ip", "-j", family, "rule", "show")
	if err != nil {
		return nil, errors.New("route_policy_query_failed")
	}
	var policies []map[string]json.RawMessage
	if json.Unmarshal(b, &policies) != nil || len(policies) == 0 {
		return nil, errors.New("route_policy_invalid")
	}
	for _, p := range policies {
		var table, src string
		_ = json.Unmarshal(p["table"], &table)
		if table == "" {
			switch string(p["table"]) {
			case "255":
				table = "local"
			case "254":
				table = "main"
			case "253":
				table = "default"
			}
		}
		_ = json.Unmarshal(p["src"], &src)
		if (table != "local" && table != "main" && table != "default") || (src != "all" && src != "") {
			return nil, errors.New("policy_routing_unsupported")
		}
		for k := range p {
			switch k {
			case "priority", "src", "table", "protocol":
			default:
				return nil, errors.New("policy_routing_unsupported")
			}
		}
	}
	return routes, nil
}

func routePrefix(r route, v6 bool) (netip.Prefix, error) {
	if r.Dst == "default" {
		if v6 {
			return netip.MustParsePrefix("::/0"), nil
		}
		return netip.MustParsePrefix("0.0.0.0/0"), nil
	}
	p, err := netip.ParsePrefix(r.Dst)
	if err != nil {
		a, e := netip.ParseAddr(r.Dst)
		if e != nil {
			return netip.Prefix{}, errors.New("route_destination_invalid")
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is6() != v6 {
		return netip.Prefix{}, errors.New("route_family_invalid")
	}
	return p.Masked(), nil
}

func routeDevice(r route) (string, error) {
	if (r.Type != "" && r.Type != "unicast") || len(r.Nexthops) != 0 || !interfacePattern.MatchString(r.Dev) || r.Dev == "lo" || strings.HasPrefix(r.Dev, "bwg") {
		return "", errors.New("route_interface_unsupported")
	}
	return r.Dev, nil
}

// Select one deterministic main-table route. A private grant crossing different
// interfaces is refused instead of silently granting only its first address.
func destinationDevice(routes []route, target netip.Prefix) (string, error) {
	bestBits, bestMetric := -1, int(^uint(0)>>1)
	var candidates []route
	for _, r := range routes {
		p, err := routePrefix(r, target.Addr().Is6())
		if err != nil {
			return "", err
		}
		if p.Bits() <= target.Bits() && p.Contains(target.Addr()) {
			if p.Bits() > bestBits || (p.Bits() == bestBits && r.Metric < bestMetric) {
				bestBits, bestMetric, candidates = p.Bits(), r.Metric, nil
			}
			if p.Bits() == bestBits && r.Metric == bestMetric {
				candidates = append(candidates, r)
			}
		}
	}
	if len(candidates) == 0 {
		return "", nil
	}
	dev := ""
	for _, r := range candidates {
		d, err := routeDevice(r)
		if err != nil || (dev != "" && dev != d) {
			return "", errors.New("route_interface_ambiguous")
		}
		dev = d
	}
	if target.Bits() > 0 {
		for _, r := range routes {
			p, _ := routePrefix(r, target.Addr().Is6())
			if p.Bits() > target.Bits() && target.Contains(p.Addr()) {
				d, err := routeDevice(r)
				if err != nil || d != dev {
					return "", errors.New("private_grant_crosses_routes")
				}
			}
		}
	}
	return dev, nil
}

func (m *Manager) desiredRules(ctx context.Context, links []spec.WireGuardLink) (map[string]Rule, error) {
	wanted := map[string]Rule{}
	hasExit := false
	seen := map[int]bool{}
	for _, c := range links {
		if !c.Exit {
			continue
		}
		if c.Slot < 1 || c.Slot > 16383 || seen[c.Slot] || c.PrivateAccess.Validate() != nil || (c.PrivateAccess != nil && c.PrivateAccess.Mode == "internal") {
			return nil, errors.New("invalid_wireguard_forwarding_link")
		}
		seen[c.Slot], hasExit = true, true
	}
	if !hasExit {
		return wanted, nil
	}
	for _, v6 := range []bool{false, true} {
		routes, err := m.routes(ctx, v6)
		if err != nil {
			return nil, err
		}
		defaultPrefix := netip.MustParsePrefix("0.0.0.0/0")
		if v6 {
			defaultPrefix = netip.MustParsePrefix("::/0")
		}
		defaultDev, err := destinationDevice(routes, defaultPrefix)
		if err != nil {
			return nil, err
		}
		for _, c := range links {
			if !c.Exit {
				continue
			}
			add := func(dev, dst, proto, port string) {
				r := Rule{Slot: c.Slot, In: c.Interface(), Out: dev, Source: c.Address(false, v6), Destination: dst, Protocol: proto, DestinationPort: port}
				wanted[r.key()] = r
				r.In, r.Out, r.Source, r.Destination, r.SourcePort, r.DestinationPort = r.Out, r.In, r.Destination, r.Source, port, ""
				wanted[r.key()] = r
			}
			if defaultDev != "" {
				for _, proto := range []string{"tcp", "udp"} {
					add(defaultDev, "any", proto, "")
				}
			}
			for _, grant := range c.PrivateAccess.EffectiveRules() {
				prefix, _ := grant.Prefix()
				if prefix.Addr().Is6() != v6 {
					continue
				}
				dev, err := destinationDevice(routes, prefix)
				if err != nil || dev == "" {
					return nil, fmt.Errorf("private_grant_route_unavailable: slot %d", c.Slot)
				}
				if dev == defaultDev {
					continue // The nft destination ACL still restricts this allowance.
				}
				protos := []string{grant.Protocol}
				if grant.Protocol == "" {
					protos = []string{"tcp", "udp"}
				}
				port := ""
				if grant.PortStart > 0 {
					port = strconv.Itoa(grant.PortStart)
					if grant.PortEnd != grant.PortStart {
						port += ":" + strconv.Itoa(grant.PortEnd)
					}
				}
				for _, proto := range protos {
					add(dev, prefix.String(), proto, port)
				}
			}
		}
	}
	if len(wanted) == 0 {
		return nil, errors.New("no_forwarding_route")
	}
	return wanted, nil
}

func sortedKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
