package agentproto

import "net/netip"

// PublicAddresses is an observation of outbound public addresses, not a claim
// about inbound reachability. Empty families mean unknown, never deletion.
type PublicAddresses struct {
	SampledAt int64  `json:"sampled_at"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
}

func ValidPublicAddress(value string, v6 bool) bool {
	a, err := netip.ParseAddr(value)
	return err == nil && a.Zone() == "" && !a.Is4In6() && a.Is6() == v6 && a.IsGlobalUnicast() && !a.IsPrivate() && !netip.MustParsePrefix("100.64.0.0/10").Contains(a)
}
