package egressguard

import (
	"context"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"strings"
	"testing"
)

func TestScopedUpstreamsAndDisableLifecycle(t *testing.T) {
	opt := Options{ProtectedPorts: []int{9101}, Upstreams: []spec.EgressUpstream{{CIDR: "10.10.0.2", Protocol: "tcp", Port: 1080}, {CIDR: "2001:db8::10", Protocol: "udp", Port: 53}, {CIDR: "127.0.0.1", Protocol: "tcp", Port: 9101}}}
	script := Script(998, opt)
	for _, want := range []string{"ip daddr 10.10.0.2/32 tcp dport 1080 accept", "ip6 daddr 2001:db8::10/128 udp dport 53 accept"} {
		if !strings.Contains(script, want) {
			t.Fatal("missing narrow exception", script)
		}
	}
	if strings.Index(script, "skuid != 0") > strings.Index(script, "dport 9101 accept") {
		t.Fatal("exception bypasses control protection")
	}
	var installed string
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		installed = stdin
		return nil, nil
	}}
	if err := g.Apply(context.Background(), 998, opt); err != nil {
		t.Fatal(err)
	}
	// A fresh process must replace a persisted table, even when the desired private guard is off.
	restarted := &Guard{Run: g.Run}
	opt.Disabled = true
	if err := restarted.Apply(context.Background(), 998, opt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(installed, "delete table inet bosun_egress") || !strings.Contains(installed, "skuid != 0") || strings.Contains(installed, "skuid 998") {
		t.Fatal("disable retained destination rules or removed API protection", installed)
	}
	if restarted.Status().Enabled {
		t.Fatal("disabled guard reported enabled")
	}
	opt.Disabled = false
	if err := restarted.Apply(context.Background(), 998, opt); err != nil || !strings.Contains(installed, "10.10.0.2/32 tcp dport 1080") || !restarted.Status().Enabled {
		t.Fatal("enable failed", err)
	}
}
func TestFreshDisabledGuardDeletesPersistedTableAndReportsFailure(t *testing.T) {
	failDelete := true
	deletes := 0
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "list" {
			return []byte("table inet other\ntable inet bosun_egress\n"), nil
		}
		if strings.HasPrefix(stdin, "delete table inet bosun_egress") {
			deletes++
			if failDelete {
				return nil, errors.New("permission denied")
			}
		}
		return nil, nil
	}}
	if err := g.Apply(context.Background(), 998, Options{Disabled: true}); err == nil || g.Status().Error == "" {
		t.Fatal("delete failure hidden")
	}
	failDelete = false
	if err := g.Apply(context.Background(), 998, Options{Disabled: true}); err != nil || deletes != 2 {
		t.Fatal("cleanup not retried", err, deletes)
	}
	if err := g.Apply(context.Background(), 998, Options{Disabled: true}); err != nil || deletes != 2 {
		t.Fatal("unchanged clean state reapplied")
	}
}
func TestInvalidExceptionLeavesInstalledPolicy(t *testing.T) {
	runs := 0
	g := &Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) { runs++; return nil, nil }}
	if err := g.Apply(context.Background(), 998, Options{}); err != nil {
		t.Fatal(err)
	}
	bad := Options{Upstreams: []spec.EgressUpstream{{CIDR: "10.10.0.2", Protocol: "tcp; accept", Port: 1080}}}
	if err := g.Apply(context.Background(), 998, bad); err == nil || runs != 1 {
		t.Fatal("bad policy changed kernel state")
	}
	if strings.Contains(Script(998, bad), "tcp; accept") {
		t.Fatal("render interpolated invalid exception")
	}
}
