package netdiag

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestExitToolBoundary(t *testing.T) {
	for _, in := range []spec.DiagnosticRequest{{Type: "exit", Target: "https://example.com"}, {Type: "exit", SourceIP: "--proxy=example.com"}, {Type: "exit", Resolver: "192.0.2.10"}, {Type: "dns", Target: "example.com", Services: true}} {
		if in.Validate() == nil {
			t.Fatal("unsafe input", in)
		}
	}
	args := geoCheckArgs(spec.DiagnosticRequest{Type: "exit", SourceIP: "192.0.2.10"})
	for _, flag := range []string{"--interface", "192.0.2.10", "--no-access", "--no-ai"} {
		if !strings.Contains(strings.Join(args, " "), flag) {
			t.Fatal(args)
		}
	}
	dir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "tools")); err != nil {
		t.Fatal(err)
	}
	if _, err := privateToolDir(dir); err == nil {
		t.Fatal("symlink tool directory accepted")
	}
	var buf exitBuffer
	buf.Write(make([]byte, maxExitReport+5))
	if !buf.overflow || len(buf.data) != maxExitReport {
		t.Fatal("unbounded report")
	}
	for _, raw := range []string{`{"schema":2}`, `{"schema":1,"identity":{"ipv4":"example.com"}}`, `<html>failure</html>`} {
		if _, out := validateExitReport([]byte(raw)); out != "invalid_report" {
			t.Fatal(raw, out)
		}
	}
	raw := []byte(`{"schema":1,"identity":{"ipv4":"192.0.2.10","ipv6":"2001:db8::1"},"stash_checks":[{"name":"Example","state":"unknown"}]}`)
	if report, out := validateExitReport(raw); out != "ok" || !json.Valid(report) {
		t.Fatal(out)
	}
}
func TestExitToolTimeoutAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "geocheck")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if _, out := executeGeoCheck(ctx, path, spec.DiagnosticRequest{Type: "exit"}); out != "timeout" {
		t.Fatal(out)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nhead -c 150000 /dev/zero\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, out := executeGeoCheck(context.Background(), path, spec.DiagnosticRequest{Type: "exit"}); out != "report_too_large" {
		t.Fatal(out)
	}
}
func TestInstalledGeoCheckSchema(t *testing.T) {
	path := os.Getenv("BOSUN_TEST_GEOCHECK")
	if path == "" {
		t.Skip("release pipeline supplies the real pinned tool")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--demo", "--json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if _, result := validateExitReport(out); result != "ok" {
		t.Fatalf("pinned upstream schema changed: %s", result)
	}
}
