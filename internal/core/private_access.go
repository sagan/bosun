package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// PrivateRoutes intersects permissions with the existing ordered route list.
// It never converts an allow into an unconditional direct rule. The caller
// places these rules before the ordinary private-destination rejection, but
// after managed transit routing and audit blocks.
func PrivateRoutes(kind string, node *spec.Node, inbounds []spec.Inbound, users []spec.User, normal, outbounds []any, final string) ([]any, []any, error) {
	grants, err := node.PrivateGrants(users)
	if err != nil {
		return nil, nil, err
	}
	tags := map[string]bool{}
	for _, ib := range inbounds {
		tag := ib.Tag
		if ib.ShadowTLS != nil {
			tag = spec.ShadowTLSTag(tag)
		}
		tags[tag] = true
	}
	if kind == "xray" {
		for _, c := range node.ReverseClients {
			tags[spec.ReverseTag(c.ID)+"-exit"] = true
		}
	}
	if final == "" {
		final = "direct"
	}
	inkey, outkey, userkey := "inbound", "outbound", "auth_user"
	if kind == "xray" {
		inkey, outkey, userkey = "inboundTag", "outboundTag", "user"
	}
	byTag := map[string]map[string]any{}
	for _, o := range outbounds {
		v := o.(map[string]any)
		tag, _ := v["tag"].(string)
		byTag[tag] = v
	}
	var result, extra []any
	clones := map[string]string{}
	for _, grant := range grants {
		if !tags[grant.Inbound] {
			continue
		}
		routes := append(append([]any{}, normal...), map[string]any{outkey: final})
		// Reverse exits have always bypassed the exit node's ordinary split
		// routes. Preserve that behavior; audit blocks are added by the caller.
		if strings.HasPrefix(grant.Inbound, "reverse-") && strings.HasSuffix(grant.Inbound, "-exit") {
			routes = []any{map[string]any{outkey: "direct"}}
		}
		for _, access := range grant.Rules {
			for _, item := range routes {
				if len(result) >= 16384 || len(extra) >= 4096 {
					return nil, nil, fmt.Errorf("private access exceeds compiled rule limit")
				}
				rule := copyMap(item.(map[string]any))
				if inbound, ok := rule[inkey]; ok && !slices.Contains(stringList(inbound), grant.Inbound) {
					continue
				}
				rule[inkey] = []string{grant.Inbound}
				if grant.UserID != 0 {
					if names, ok := rule[userkey]; ok && !slices.Contains(stringList(names), grant.UserName) {
						continue
					}
					rule[userkey] = []string{grant.UserName}
				}
				baseTag, _ := rule[outkey].(string)
				blocked := baseTag == "block" || rule["action"] == "reject"
				if !blocked {
					base, ok := byTag[baseTag]
					if !ok {
						return nil, nil, fmt.Errorf("private access route has unknown outbound %q", baseTag)
					}
					if (kind == "xray" && base["protocol"] != "freedom") || (kind == "singbox" && base["type"] != "direct") {
						return nil, nil, fmt.Errorf("private access requires a direct dial socket for %q", baseTag)
					}
					key := fmt.Sprintf("%d/%s", grant.Mark, baseTag)
					cloneTag := clones[key]
					if cloneTag == "" {
						h := sha256.Sum256([]byte(key))
						cloneTag = fmt.Sprintf("private-%x", h[:12])
						clones[key] = cloneTag
						clone := copyMap(base)
						clone["tag"] = cloneTag
						if kind == "singbox" {
							clone["routing_mark"] = grant.Mark
						} else {
							settings, _ := clone["settings"].(map[string]any)
							if settings == nil {
								settings = map[string]any{}
							}
							if _, set := settings["domainStrategy"]; !set {
								settings["domainStrategy"] = "UseIP"
							}
							clone["settings"] = settings
							ss, _ := clone["streamSettings"].(map[string]any)
							if ss == nil {
								ss = map[string]any{}
							}
							sock, _ := ss["sockopt"].(map[string]any)
							if sock == nil {
								sock = map[string]any{}
							}
							sock["mark"] = grant.Mark
							ss["sockopt"] = sock
							clone["streamSettings"] = ss
						}
						extra = append(extra, clone)
					}
					rule[outkey] = cloneTag
				}
				if kind == "singbox" {
					permission := map[string]any{"ip_cidr": []string{access.CIDR}}
					if access.Protocol != "" {
						permission["network"] = []string{access.Protocol}
					}
					if access.PortStart > 0 {
						permission["port_range"] = []string{fmt.Sprintf("%d:%d", access.PortStart, access.PortEnd)}
					}
					action := map[string]any{"type": "logical", "mode": "and", "rules": []any{rule, permission}}
					if blocked {
						action["action"] = "reject"
						delete(rule, "action")
					} else {
						action["outbound"] = rule[outkey]
						delete(rule, outkey)
					}
					result = append(result, action)
				} else {
					if existing, ok := rule["ip"]; ok {
						ips, e := intersectPrefixes(stringList(existing), access.CIDR)
						if e != nil {
							return nil, nil, e
						}
						if len(ips) == 0 {
							continue
						}
						rule["ip"] = ips
					} else {
						rule["ip"] = []string{access.CIDR}
					}
					if access.Protocol != "" { // generated split routes currently contain no network/port matches
						if network, ok := rule["network"].(string); ok && !slices.Contains(strings.Split(network, ","), access.Protocol) {
							continue
						}
						rule["network"] = access.Protocol
					}
					if existing, ok := rule["port"].(string); ok && access.PortStart > 0 {
						var ports []string
						for _, part := range strings.Split(existing, ",") {
							start, end, e := spec.ParsePortMatch(part)
							if e != nil {
								return nil, nil, e
							}
							start = max(start, access.PortStart)
							end = min(end, access.PortEnd)
							if start <= end {
								ports = append(ports, strconv.Itoa(start)+"-"+strconv.Itoa(end))
							}
						}
						if len(ports) == 0 {
							continue
						}
						rule["port"] = strings.Join(ports, ",")
					} else if access.PortStart > 0 {
						rule["port"] = fmt.Sprintf("%d-%d", access.PortStart, access.PortEnd)
					}
					rule["type"] = "field"
					result = append(result, rule)
				}
			}
		}
	}
	if len(result) > 16384 || len(extra) > 4096 {
		return nil, nil, fmt.Errorf("private access configuration exceeds compiled rule limit")
	}
	if len(result) > 0 {
		for _, cidr := range spec.PrivateAccessProtectedRanges {
			var rule map[string]any
			if kind == "xray" {
				rule = map[string]any{"type": "field", "ip": []string{cidr}, "outboundTag": "block"}
			} else {
				rule = map[string]any{"ip_cidr": []string{cidr}, "action": "reject"}
			}
			result = append([]any{rule}, result...)
		}
	}
	return result, extra, nil
}

func stringList(v any) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	if s, ok := v.(string); ok {
		return []string{s}
	}
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func copyMap(v map[string]any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
func intersectPrefixes(list []string, cidr string) ([]string, error) {
	allow := netip.MustParsePrefix(cidr)
	var out []string
	for _, s := range list {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			if a, err := netip.ParseAddr(s); err == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return nil, fmt.Errorf("private access cannot intersect non-literal IP rule")
			}
		}
		if allow.Contains(p.Addr()) && allow.Bits() <= p.Bits() {
			out = append(out, p.Masked().String())
		} else if p.Contains(allow.Addr()) && p.Bits() <= allow.Bits() {
			out = append(out, allow.String())
		}
	}
	return out, nil
}
