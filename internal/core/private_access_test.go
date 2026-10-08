package core

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestPrivateRoutesPreserveRoutingAndMarks(t *testing.T) {
	n := &spec.Node{UserSpeedLimitMbps: 2, Inbounds: []spec.Inbound{{Tag: "allowed", Protocol: spec.VLESS, PrivateAccess: &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2", Protocol: "tcp", PortStart: 8000, PortEnd: 8090}}}}, {Tag: "denied", Protocol: spec.VLESS}}}
	u := []spec.User{{ID: 1, Name: "user"}}
	for _, kind := range []string{"singbox", "xray"} {
		t.Run(kind, func(t *testing.T) {
			outKey, typeKey, direct := "outbound", "type", "direct"
			if kind == "xray" {
				outKey, typeKey, direct = "outboundTag", "protocol", "freedom"
			}
			outs := []any{map[string]any{"tag": "direct", typeKey: direct}, map[string]any{"tag": "bound", typeKey: direct}}
			routes := []any{map[string]any{outKey: "bound", "domain": []string{"example.com"}}}
			if kind == "xray" {
				routes[0].(map[string]any)["port"] = "8080-8085"
			}
			rules, clones, err := PrivateRoutes(kind, n, n.Inbounds, u, routes, outs, "direct")
			if err != nil {
				t.Fatal(err)
			}
			if len(clones) != 4 || len(rules) != 6 {
				t.Fatalf("%d rules %d clones", len(rules), len(clones))
			}
			b, _ := json.Marshal(rules)
			if strings.Contains(string(b), "denied") || !strings.Contains(string(b), "example.com") {
				t.Fatal(string(b))
			}
			if kind == "xray" && rules[2].(map[string]any)["port"] != "8080-8085" {
				t.Fatal("port intersection lost")
			}
			g, _ := n.PrivateGrants(u)
			for i, c := range clones {
				v := c.(map[string]any)
				mark := v["routing_mark"]
				if kind == "xray" {
					mark = v["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["mark"]
				}
				if mark != g[i/2].Mark {
					t.Fatal("policy/user socket mark lost")
				}
			}
		})
	}
}
