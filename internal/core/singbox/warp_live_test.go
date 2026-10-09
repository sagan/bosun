package singbox

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/warp"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/crypto/ssh"
)

// Explicit live opt-in: supply a private WARPAccount JSON file and the pinned
// Extended binary. Reuses the account read-only; never registers or changes a
// Cloudflare account, host routes, firewall rules or running bosun services.
func TestExtendedLiveWARP(t *testing.T) {
	path, binary := os.Getenv("BOSUN_WARP_TEST_ACCOUNT"), os.Getenv("BOSUN_EXTENDED_TEST_BINARY")
	if path == "" || binary == "" {
		t.Skip("set BOSUN_WARP_TEST_ACCOUNT and BOSUN_EXTENDED_TEST_BINARY for live Cloudflare verification")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("cannot read test WARP account")
	}
	var account spec.WARPAccount
	if json.Unmarshal(raw, &account) != nil || account.PrivateKey == "" || len(account.Reserved) != 3 {
		t.Fatal("test account must have credentials and three reserved bytes")
	}
	out, err := warp.Resolve(spec.Outbound{Tag: "warp", WARP: &spec.WARP{FromNode: true}}, &account)
	if err != nil {
		t.Fatal("cannot resolve test WARP account")
	}
	for _, mode := range []string{"unused", "default", "rule"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			log := slog.New(slog.NewTextHandler(io.Discard, nil))
			c, err := New(Options{Distribution: "singbox-extended", Binary: binary, WorkDir: t.TempDir(), StatsListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(extendedPort(t)))}, log)
			if err != nil {
				t.Fatal("cannot prepare isolated core")
			}
			defer c.Stop(context.Background())
			ib := spec.Inbound{Tag: "ssh-warp", Protocol: spec.SSH, Core: "singbox-extended", Listen: "127.0.0.1", Port: extendedPort(t)}
			spec.FillInboundSecrets(&ib)
			u := spec.User{ID: 7, Name: "billing-7", UUID: "00000000-0000-4000-8000-000000000007", Password: "test-password"}
			node := &spec.Node{Inbounds: []spec.Inbound{ib}, Outbounds: []spec.Outbound{out}}
			if mode == "default" {
				node.DefaultOutbound = "warp"
			} else if mode == "rule" {
				node.Routes = []spec.RouteRule{{Match: []string{"domain:www.cloudflare.com"}, Action: "outbound", Value: "warp"}}
			}
			bundle, err := c.Render(node, node.Inbounds, []spec.User{u})
			if err != nil {
				t.Fatal("cannot render live config")
			}
			if err = c.Start(ctx, bundle); err != nil {
				t.Fatal("live config failed startup")
			}
			hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ib.SSH.PublicKey))
			if err != nil {
				t.Fatal(err)
			}
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port))
			var client *ssh.Client
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
				client, err = ssh.Dial("tcp", addr, &ssh.ClientConfig{User: spec.ProxyUsername(u.UUID, ib.Tag), Auth: []ssh.AuthMethod{ssh.Password(u.Password)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: time.Second})
				if err == nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if err != nil {
				t.Fatal("SSH proxy did not become ready")
			}
			defer client.Close()
			transport := &http.Transport{DialContext: client.DialContext, DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport, Timeout: 35 * time.Second}
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatal("Cloudflare trace request through SSH failed")
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
			resp.Body.Close()
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatal("Cloudflare trace response failed")
			}
			state := ""
			for _, line := range strings.Split(string(body), "\n") {
				if strings.HasPrefix(line, "warp=") {
					state = strings.TrimPrefix(line, "warp=")
				}
			}
			// Do not log the trace body: it contains the machine's egress IP.
			if mode == "unused" && state != "off" || mode != "unused" && state != "on" && state != "plus" {
				t.Fatal("Cloudflare did not confirm the expected direct/WARP exit")
			}
			counters, err := c.Stats(ctx, false)
			if err != nil {
				t.Fatal("cannot read traffic counters")
			}
			traffic := counters[spec.InboundUser(u.Name, ib.Tag)]
			if traffic.Up <= 0 || traffic.Down < int64(len(body)) {
				t.Fatal("SSH WARP traffic lost user/inbound accounting")
			}
			t.Logf("exit verified; user/inbound bytes: sent=%d received=%d", traffic.Up, traffic.Down)
		})
	}
}
