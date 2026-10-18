package netdiag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRouteToolAtomicVerification(t *testing.T) {
	root := t.TempDir()
	path, err := routeToolPath(root, true)
	if err != nil {
		t.Fatal(err)
	}
	good := []byte("reviewed executable fixture")
	sum := fmt.Sprintf("%x", sha256.Sum256(good))
	if err = saveRouteTool(path, sum, bytes.NewReader(good)); err != nil {
		t.Fatal(err)
	}
	if err = verifyRouteTool(path, sum); err != nil {
		t.Fatal(err)
	}
	if err = saveRouteTool(path, sum, bytes.NewReader([]byte("corrupted"))); err == nil {
		t.Fatal("accepted checksum mismatch")
	}
	if err = verifyRouteTool(path, sum); err != nil {
		t.Fatal("failed replacement damaged existing file")
	}
	if err = os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if verifyRouteTool(path, sum) == nil {
		t.Fatal("accepted writable executable")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(root, "outside"), path)
	if verifyRouteTool(path, sum) == nil {
		t.Fatal("accepted symlink")
	}
}
func TestRouteToolDirectorySafety(t *testing.T) {
	root := t.TempDir()
	os.Symlink(t.TempDir(), filepath.Join(root, "tools"))
	if _, err := routeToolPath(root, true); err == nil {
		t.Fatal("symlink accepted")
	}
	for _, r := range []spec.DiagnosticRequest{{Type: "route_tool_install", Target: "https://example.com/tool"}, {Type: "route_tool_check", SourceIP: "192.0.2.10"}, {Type: "route_tool_install", Route: &spec.ReturnRouteRequest{City: "beijing", Family: "ipv4"}}} {
		if r.Validate() == nil {
			t.Fatal("accepted arbitrary tool input")
		}
	}
}
func TestNextTraceReport(t *testing.T) {
	raw := []byte(`{"Hops":[[{"Success":true,"TTL":1,"Address":{"IP":"192.0.2.10"},"RTT":1500000}],[{"Success":false,"TTL":2}]],"StopReason":{"hop":1,"reason":"unreachable"}}`)
	hops, ok := parseNextTrace(raw)
	if !ok || len(hops) != 2 || *hops[0].RTT != 1.5 || hops[0].Reply == "" || hops[1].IP != "" {
		t.Fatalf("bad report %+v", hops)
	}
	for _, raw := range []string{`{}`, `{"Hops":[[{"TTL":4}]]}`, `{"Hops":[[{"TTL":1,"Success":true,"Address":{"IP":"invalid"}}]]}`} {
		if _, ok := parseNextTrace([]byte(raw)); ok {
			t.Fatal("accepted malformed report")
		}
	}
}

// Explicitly opted-in Linux integration: separate temp data root, no running
// agent changes. Downloads only the pinned binary and probes fixed public targets.
func TestRouteToolLive(t *testing.T) {
	if os.Getenv("BOSUN_TEST_ROUTE_TOOLS") != "1" || runtime.GOOS != "linux" {
		t.Skip("opt-in Linux integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	root := t.TempDir()
	s, outcome := runRouteTool(ctx, root, true)
	if outcome != "ok" || s.Engine != "nexttrace" || !s.Managed {
		t.Fatalf("install/self-check: %+v %s", s, outcome)
	}
	s, outcome = runRouteTool(ctx, root, false)
	if outcome != "ok" {
		t.Fatalf("recheck %+v", s)
	}
	r, outcome := runReturnRoute(ctx, spec.ReturnRouteRequest{City: "beijing", Family: "ipv4"}, root)
	if r.Engine != "nexttrace" || len(r.Paths) != 3 {
		t.Fatalf("wrong engine/report: %s %s", r.Engine, outcome)
	}
	for _, p := range r.Paths {
		if len(p.Hops) == 0 || p.Outcome == "invalid_report" || p.Outcome == "failed" {
			t.Fatalf("parse/execute failed: %s %s", p.Carrier, p.Outcome)
		}
		t.Log(p.Carrier, p.Outcome, "hops", len(p.Hops), "reached", p.Reached)
	}
}
