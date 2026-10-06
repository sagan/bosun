package spec

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

func CheckReverseOverride(patch json.RawMessage) error {
	if len(patch) == 0 {
		return nil
	}
	var v map[string]any
	if err := json.Unmarshal(patch, &v); err != nil {
		return err
	}
	for _, key := range []string{"routing", "outbounds", "policy"} {
		if _, ok := v[key]; ok {
			return fmt.Errorf("managed reverse connections cannot override Xray %s; use the routing editor", key)
		}
	}
	return nil
}

// ReverseInbound is an explicitly managed Xray reverse endpoint. A receiver
// authenticates only its tunnel identity; an ordinary endpoint keeps normal
// users and routes exclusively to this link. IDs are stable across edits.
type ReverseInbound struct {
	ID       string `json:"id"`
	Receiver bool   `json:"receiver,omitempty"`
	UUID     string `json:"uuid,omitempty"`
}

func ReverseTag(id string) string     { return "reverse-" + id }
func ReverseEmail(id string) string   { return "reverse-control-" + id }
func IsReverseEmail(name string) bool { return strings.HasPrefix(name, "reverse-control-") }

// ReverseClient actively connects from the exit to a transit. Settings only
// contain client-side TLS material, never the transit's REALITY private key.
type ReverseClient struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
	UUID string `json:"uuid"`
	TLS  *TLS   `json:"tls,omitempty"`
}

func (c ReverseClient) Validate() error {
	if !ValidTag(c.ID) || c.Host == "" || (net.ParseIP(c.Host) == nil && strings.ContainsAny(c.Host, " /:[]\r\n")) || c.Port < 1 || c.Port > 65535 || c.UUID == "" {
		return fmt.Errorf("invalid reverse client identity or endpoint")
	}
	if c.TLS != nil && c.TLS.Mode == TLSReality && (c.TLS.Reality == nil || c.TLS.Reality.PublicKey == "" || c.TLS.Reality.PrivateKey != "") {
		return fmt.Errorf("reverse client requires only the REALITY public key")
	}
	return nil
}

func (r ReverseInbound) Validate(ib Inbound) error {
	if !CapabilitiesForCore("xray").Supports(ib) {
		return fmt.Errorf("reverse user protocol or transport is unsupported by Xray")
	}
	if !ValidTag(r.ID) || ib.Core != "xray" {
		return fmt.Errorf("reverse inbound requires a valid link ID and Xray")
	}
	if r.Receiver && (ib.Protocol != VLESS || ib.TransportType() != "tcp" || r.UUID == "") {
		return fmt.Errorf("reverse receiver requires VLESS TCP and a tunnel identity")
	}
	if !r.Receiver && (ib.Protocol == WireGuard || ib.Protocol == SOCKS || ib.Protocol == HTTP) {
		return fmt.Errorf("reverse user inbound requires a protocol with per-user traffic accounting")
	}
	return nil
}
