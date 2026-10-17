package xray

import (
	"fmt"
	"reflect"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// The kernel owns WireGuard; Xray opens ordinary, source-bound dial sockets.
// Subscriber emails and traffic counters remain on A's original inbounds.
func wireGuardRoutes(node *spec.Node, inbounds []spec.Inbound, users []spec.User) ([]any, []any, error) {
	if err := node.ValidateWireGuardLinks(); err != nil {
		return nil, nil, err
	}
	links := map[int]spec.WireGuardLink{}
	for _, c := range node.WireGuardLinks {
		links[c.Slot] = c
	}
	var rules, outs []any
	seen := map[string]bool{}
	for _, ib := range inbounds {
		if ib.WireGuardSlot == 0 {
			continue
		}
		c, ok := links[ib.WireGuardSlot]
		if !ok || c.Exit {
			return nil, nil, fmt.Errorf("missing WireGuard transit link")
		}
		// Render may receive a core-specific inbound slice rather than exactly
		// node.Inbounds. Validate that slice too; never let caller selection
		// bypass transport ownership or destination authorization.
		if err := ib.Validate(); err != nil {
			return nil, nil, err
		}
		if !reflect.DeepEqual(ib.PrivateAccess.EffectiveRules(), c.PrivateAccess.EffectiveRules()) {
			return nil, nil, fmt.Errorf("WireGuard inbound and link private grants must match")
		}
		add := func(v6 bool, user *spec.User) {
			family, strategy := "v4", "UseIPv4"
			if v6 {
				family, strategy = "v6", "UseIPv6"
			}
			tag := fmt.Sprintf("wireguard-%d-%s", c.Slot, family)
			out := m{"protocol": "freedom", "sendThrough": c.Address(false, v6), "settings": m{"domainStrategy": strategy}}
			rule := m{"type": "field", "inboundTag": []string{ib.Tag}}
			if v6 {
				rule["ip"] = []string{"::/0"}
			}
			if user != nil {
				tag += fmt.Sprintf("-u%d", user.ID)
				out["streamSettings"] = m{"sockopt": m{"mark": spec.SpeedMark(user.ID)}}
				rule["user"] = []string{spec.InboundUser(user.Name, ib.Tag)}
			}
			out["tag"], rule["outboundTag"] = tag, tag
			if !seen[tag] {
				outs = append(outs, out)
				seen[tag] = true
			}
			rules = append(rules, rule)
		}
		for _, u := range ib.EffectiveUsers(users) {
			if node.EffectiveSpeedLimit(u) > 0 {
				add(true, &u)
				add(false, &u)
			}
		}
		add(true, nil)
		add(false, nil)
	}
	return rules, outs, nil
}
