package spec

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// CoreCapabilities describes the features implemented by a bosun adapter,
// rather than everything the upstream binary may support.
type CoreCapabilities struct {
	Protocols       []Protocol `json:"protocols"`
	Transports      []string   `json:"transports,omitempty"`
	Shadowsocks2022 bool       `json:"shadowsocks2022,omitempty"`
	HotUserReload   bool       `json:"hot_user_reload,omitempty"`
	Fallbacks       bool       `json:"fallbacks,omitempty"`
	ProxyProtocol   bool       `json:"proxy_protocol,omitempty"`
	SnellMultiUser  bool       `json:"snell_multi_user,omitempty"`
	SnellObfsTLS    bool       `json:"snell_obfs_tls,omitempty"`
	ShadowTLS       bool       `json:"shadow_tls,omitempty"`
}

func (c CoreCapabilities) Supports(ib Inbound) bool { return c.UnsupportedReason(ib) == "" }

// UnsupportedReason is a stable, translatable reason code. Shape validation
// (keys, addresses, required TLS, etc.) remains Inbound.Validate's job.
func (c CoreCapabilities) UnsupportedReason(ib Inbound) string {
	switch {
	case !slices.Contains(c.Protocols, ib.Protocol):
		return "protocol"
	case ib.Protocol == Shadowsocks && strings.HasPrefix(ib.Cipher, "2022-") && !c.Shadowsocks2022:
		return "ss2022"
	case ib.ShadowTLS != nil && !c.ShadowTLS:
		return "shadowTLS"
	case len(ib.Fallbacks) > 0 && !c.Fallbacks:
		return "fallbacks"
	case ib.AcceptProxyProtocol && !c.ProxyProtocol:
		return "proxyProtocol"
	case ib.Protocol == Snell && ib.SnellMultiUser && !c.SnellMultiUser:
		return "snellMultiUser"
	case ib.Protocol == Snell && strings.EqualFold(ib.SnellObfs, "tls") && !c.SnellObfsTLS:
		return "snellTLS"
	case ib.TransportType() != "tcp" && !slices.Contains(c.Transports, ib.TransportType()):
		return "transport"
	default:
		return ""
	}
}

type CoreCandidate struct {
	Name         string           `json:"name"`
	Capabilities CoreCapabilities `json:"capabilities"`
}

// CoreCatalog is also the default preference order. Each call returns fresh
// values so a registry/test cannot mutate the shared catalog.
func CoreCatalog() []CoreCandidate {
	return []CoreCandidate{
		{"singbox", CoreCapabilities{Protocols: []Protocol{VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, SOCKS, HTTP, Naive, Snell}, Transports: []string{"ws", "grpc", "httpupgrade", "http"}, Shadowsocks2022: true, SnellMultiUser: true, ShadowTLS: true}},
		{"xray", CoreCapabilities{Protocols: []Protocol{VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP, WireGuard}, Transports: []string{"ws", "grpc", "httpupgrade", "xhttp"}, HotUserReload: true, Fallbacks: true, ProxyProtocol: true}},
		{"mita", CoreCapabilities{Protocols: []Protocol{Mieru}, HotUserReload: true}},
		{"hysteria", CoreCapabilities{Protocols: []Protocol{Hysteria2}, HotUserReload: true}},
		{"snell", CoreCapabilities{Protocols: []Protocol{Snell}, SnellObfsTLS: true}},
	}
}

func CapabilitiesForCore(name string) CoreCapabilities {
	for _, c := range CoreCatalog() {
		if c.Name == name {
			return c.Capabilities
		}
	}
	return CoreCapabilities{}
}

// SelectCore is shared by the runtime registry and the panel preview. The
// supplied candidates must be enabled, in the node's configured priority order.
func SelectCore(ib Inbound, enabled []CoreCandidate) (string, error) {
	if ib.Core != "" {
		for _, c := range enabled {
			if c.Name != ib.Core {
				continue
			}
			if reason := c.Capabilities.UnsupportedReason(ib); reason != "" {
				return "", fmt.Errorf("inbound %q: core %q does not support %s over %s (%s)", ib.Tag, ib.Core, ib.Protocol, ib.TransportType(), reason)
			}
			return c.Name, nil
		}
		return "", fmt.Errorf("inbound %q wants core %q which is not enabled", ib.Tag, ib.Core)
	}
	// Xray's REALITY fallback rate limit protects discovered nodes from abuse.
	if ib.TLS != nil && ib.TLS.Mode == TLSReality {
		for _, c := range enabled {
			if c.Name == "xray" && c.Capabilities.Supports(ib) {
				return c.Name, nil
			}
		}
	}
	for _, c := range enabled {
		if c.Capabilities.Supports(ib) {
			return c.Name, nil
		}
	}
	return "", fmt.Errorf("inbound %q: no enabled core supports %s over %s", ib.Tag, ib.Protocol, ib.TransportType())
}

type CoreOption struct {
	Name       string `json:"name"`
	Compatible bool   `json:"compatible"`
	Reason     string `json:"reason,omitempty"`
	Available  *bool  `json:"available"` // nil means the node has not advertised capabilities
}
type CoreOptions struct {
	Options        []CoreOption `json:"options"`
	InventoryKnown bool         `json:"inventory_known"`
	AutoCore       string       `json:"auto_core"`
}

// PreviewCores keeps unsupported choices in the API for explaining an existing
// pin. The UI filters those choices unless one is currently selected. nil
// inventory means an older/unreported node, not a node with no enabled cores.
func PreviewCores(ib Inbound, inventory []CoreCandidate) CoreOptions {
	out := CoreOptions{Options: []CoreOption{}, InventoryKnown: inventory != nil}
	catalog := CoreCatalog()
	for _, c := range inventory {
		i := slices.IndexFunc(catalog, func(x CoreCandidate) bool { return x.Name == c.Name })
		if i >= 0 {
			catalog[i] = c
		} else {
			catalog = append(catalog, c)
		}
	}
	for _, c := range catalog {
		reason := c.Capabilities.UnsupportedReason(ib)
		opt := CoreOption{Name: c.Name, Compatible: reason == "", Reason: reason}
		if inventory != nil {
			enabled := slices.ContainsFunc(inventory, func(x CoreCandidate) bool { return x.Name == c.Name })
			opt.Available = &enabled
		}
		out.Options = append(out.Options, opt)
	}
	if inventory != nil {
		ib.Core = ""
		out.AutoCore, _ = SelectCore(ib, inventory)
	}
	return out
}

// CoreProbe reads only capability-relevant, non-secret fields. Credentials
// must never be placed in URLs, browser query caches or HTTP access logs.
func CoreProbe(q url.Values) Inbound {
	ib := Inbound{Protocol: Protocol(q.Get("protocol")), Cipher: q.Get("cipher"), Transport: &Transport{Type: q.Get("transport")}, AcceptProxyProtocol: q.Get("proxy_protocol") == "true", SnellMultiUser: q.Get("snell_multi_user") == "true", SnellObfs: q.Get("snell_obfs")}
	if q.Get("reality") == "true" {
		ib.TLS = &TLS{Mode: TLSReality}
	}
	if q.Get("shadow_tls") == "true" {
		ib.ShadowTLS = &ShadowTLS{}
	}
	if q.Get("fallbacks") == "true" {
		ib.Fallbacks = []Fallback{{}}
	}
	return ib
}
