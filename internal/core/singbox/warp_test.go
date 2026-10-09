package singbox

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/warp"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func warpFixture(t *testing.T) spec.Outbound {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	o, err := warp.Resolve(spec.Outbound{Tag: "warp", WARP: &spec.WARP{FromNode: true}}, &spec.WARPAccount{
		PrivateKey: key, PeerPublicKey: key, Endpoint: "192.0.2.10:2408",
		Addresses: []string{"10.10.0.2/32"}, Reserved: []int{1, 2, 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestWARPRenderDistributions(t *testing.T) {
	o := warpFixture(t)
	o.ProxyTag = "direct"
	node := &spec.Node{Outbounds: []spec.Outbound{o}, DefaultOutbound: o.Tag}
	inbounds := []spec.Inbound{{Tag: "in", Protocol: spec.VLESS, Port: 24450}}
	before, _ := json.Marshal(node)
	// Rendering Extended must not strip the shared account's reserved bytes:
	// the same node is subsequently rendered for official sing-box too.
	for _, distribution := range []string{"singbox-extended", "singbox", ""} {
		t.Run("distribution="+distribution, func(t *testing.T) {
			raw, err := render(node, inbounds, users, renderOptions{Distribution: distribution})
			if err != nil {
				t.Fatal(err)
			}
			cfg := decode(t, raw)
			endpoint := cfg["endpoints"].([]any)[0].(map[string]any)
			peer := endpoint["peers"].([]any)[0].(map[string]any)
			reserved, present := peer["reserved"]
			if distribution == "singbox-extended" {
				if present {
					t.Fatal("Extended rejects the official WireGuard reserved field")
				}
			} else if !reflect.DeepEqual(reserved, []any{float64(1), float64(2), float64(3)}) {
				t.Fatal("official sing-box lost reserved bytes")
			}
			if endpoint["type"] != "wireguard" || endpoint["detour"] != "direct" || endpoint["mtu"] != float64(1280) || endpoint["private_key"] != o.WARP.PrivateKey ||
				peer["address"] != "192.0.2.10" || peer["port"] != float64(2408) || peer["public_key"] != o.WARP.PeerPublicKey ||
				peer["persistent_keepalive_interval"] != float64(25) || cfg["route"].(map[string]any)["final"] != "warp" {
				t.Fatal("WARP account, transport or routing changed")
			}
			after, _ := json.Marshal(node)
			if string(before) != string(after) {
				t.Fatal("render mutated shared WARP credentials")
			}
		})
	}
}

// Checks both pinned distributions against real parsers, without a Cloudflare
// account or network connection. In CI, download checksum-verified test cores.
func TestWARPRealConfigs(t *testing.T) {
	for _, tc := range []struct{ distribution, env string }{
		{"singbox", "BOSUN_SINGBOX_TEST_BINARY"},
		{"singbox-extended", "BOSUN_EXTENDED_TEST_BINARY"},
	} {
		t.Run(tc.distribution, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			binary := os.Getenv(tc.env)
			if binary == "" && os.Getenv("BOSUN_TEST_DOWNLOAD_CORES") == "1" {
				// Extended deliberately remains caution in the catalog because
				// of its protocol limitations, but still needs parser coverage.
				release, ok := coreinstall.Default(tc.distribution)
				if !ok {
					t.Fatal("no reviewed core release")
				}
				var err error
				binary, err = coreinstall.New(t.TempDir(), log).Ensure(ctx, tc.distribution, release.Version)
				if err != nil {
					t.Fatal(err)
				}
			}
			if binary == "" {
				t.Skip("set " + tc.env + " or BOSUN_TEST_DOWNLOAD_CORES=1")
			}
			c, err := New(Options{Distribution: tc.distribution, Binary: binary, WorkDir: t.TempDir()}, log)
			if err != nil {
				t.Fatal(err)
			}
			protocols := []spec.Protocol{spec.VLESS}
			if tc.distribution == "singbox-extended" {
				protocols = append(protocols, spec.SSH, spec.Mieru)
			}
			for _, protocol := range protocols {
				for _, mode := range []string{"unused", "default", "rule"} {
					t.Run(string(protocol)+"/"+mode, func(t *testing.T) {
						ib := spec.Inbound{Tag: "in", Protocol: protocol, Port: 24450, Core: tc.distribution}
						spec.FillInboundSecrets(&ib)
						node := &spec.Node{Inbounds: []spec.Inbound{ib}, Outbounds: []spec.Outbound{warpFixture(t)}}
						if mode == "default" {
							node.DefaultOutbound = "warp"
						} else if mode == "rule" {
							node.Routes = []spec.RouteRule{{Match: []string{"domain:example.com"}, Action: "outbound", Value: "warp"}}
						}
						bundle, err := c.Render(node, node.Inbounds, users)
						if err != nil {
							t.Fatal(err)
						}
						if err = c.Check(ctx, bundle); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		})
	}
}
