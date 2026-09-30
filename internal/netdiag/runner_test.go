package netdiag

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/dns/dnsmessage"
)

func TestServicesAndDownloadBudget(t *testing.T) {
	var r Runner
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/redirect":
			w.Header().Set("Location", "/never")
			w.WriteHeader(302)
		case "/never":
			t.Error("followed redirect")
		case "/download":
			block := make([]byte, 1<<20)
			for i := 0; i < 66; i++ {
				if _, err := w.Write(block); err != nil {
					return
				}
			}
		case "/bad":
			w.WriteHeader(503)
		default:
			w.WriteHeader(204)
		}
	}))
	defer srv.Close()
	for _, tc := range []struct{ kind, path, want string }{
		{"tcp", "", "ok"}, {"http", "/", "ok"}, {"http", "/bad", "http_status"},
		{"http", "/redirect", "ok"}, {"download", "/redirect", "http_status"},
		{"download", "/", "empty"}, {"download", "/download", "ok"},
	} {
		target := srv.URL + tc.path
		if tc.kind == "tcp" {
			target = strings.TrimPrefix(srv.URL, "http://")
		}
		out := r.Run(ctx, spec.DiagnosticRequest{Type: tc.kind, Target: target, SourceIP: "127.0.0.1"})
		if out.Outcome != tc.want || out.Measurement == nil {
			t.Fatalf("%+v: %+v", tc, out)
		}
		if tc.path == "/download" && (out.Measurement.Bytes != 64<<20 || out.Measurement.Mbps <= 0) {
			t.Fatalf("budget: %+v", out)
		}
	}
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer tlsServer.Close()
	if got := r.Run(ctx, spec.DiagnosticRequest{Type: "http", Target: tlsServer.URL}); got.Outcome != "tls" {
		t.Fatal(got)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if got := r.Run(ctx, spec.DiagnosticRequest{Type: "tcp", Target: addr}); got.Outcome != "refused" || got.Measurement.LatencyMs >= 0 {
		t.Fatal(got)
	}
}

func TestBusyCancellationAndReuse(t *testing.T) {
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer srv.Close()
	var r Runner
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan spec.DiagnosticResult, 1)
	go func() { done <- r.Run(ctx, spec.DiagnosticRequest{Type: "http", Target: srv.URL}) }()
	<-entered
	if got := r.Run(ctx, spec.DiagnosticRequest{Type: "dns", Target: "example.com"}); got.Outcome != "busy" {
		t.Fatal(got)
	}
	cancel()
	if got := <-done; got.Outcome != "canceled" {
		t.Fatal(got)
	}
	if r.busy.Load() {
		t.Fatal("busy flag leaked")
	}
}

func TestDNSCustomResolver(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var msg dnsmessage.Message
			if msg.Unpack(buf[:n]) != nil {
				continue
			}
			msg.Header.Response = true
			msg.Header.RecursionAvailable = true
			for _, q := range msg.Questions {
				h := dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: dnsmessage.ClassINET, TTL: 60}
				if q.Type == dnsmessage.TypeA {
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}})
				}
				if q.Type == dnsmessage.TypeAAAA {
					msg.Answers = append(msg.Answers, dnsmessage.Resource{Header: h, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}})
				}
			}
			b, _ := msg.Pack()
			_, _ = conn.WriteTo(b, addr)
		}
	}()
	var r Runner
	out := r.Run(context.Background(), spec.DiagnosticRequest{Type: "dns", Target: "example.com", Resolver: conn.LocalAddr().String(), SourceIP: "127.0.0.1"})
	conn.Close()
	<-done
	if out.Outcome != "ok" || len(out.Addresses) != 2 {
		t.Fatal(out)
	}
}

func TestRouteFixedArgumentsBoundedOutputAndDeadline(t *testing.T) {
	in := spec.DiagnosticRequest{Type: "mtr", Target: "example.com", SourceIP: "10.10.0.2"}
	if got := routeArgs(in, net.ParseIP("192.0.2.10")); !reflect.DeepEqual(got, []string{"-4", "-n", "-m", "20", "-r", "-c", "5", "-i", "0.2", "-a", "10.10.0.2", "192.0.2.10"}) {
		t.Fatal(got)
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	var r Runner
	in = spec.DiagnosticRequest{Type: "mtr", Target: "127.0.0.1"}
	if got := r.Run(context.Background(), in); got.Outcome != "unavailable" {
		t.Fatal(got)
	}
	path := filepath.Join(dir, "mtr")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ni=0\nwhile [ $i -lt 5000 ]; do printf '1234567890'; i=$((i+1)); done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if got := r.Run(context.Background(), in); got.Outcome != "ok" || !got.Truncated || len(got.Output) != MaxOutput {
		t.Fatalf("output outcome=%s len=%d", got.Outcome, len(got.Output))
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec /bin/sleep 5\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if got := r.Run(ctx, in); got.Outcome != "timeout" || time.Since(start) > 2*time.Second {
		t.Fatal(got)
	}
	var b boundedOutput
	b.Write([]byte("safe\x1b\x00\r\n\ttext\xff"))
	if b.text() != "safe\n\ttext" {
		t.Fatal(b.text())
	}
}

func TestInstalledRouteTools(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux node tools")
	}
	for _, kind := range []string{"mtr", "traceroute"} {
		t.Run(kind, func(t *testing.T) {
			if _, err := exec.LookPath(kind); err != nil {
				t.Skip("optional tool not installed")
			}
			var r Runner
			out := r.Run(context.Background(), spec.DiagnosticRequest{Type: kind, Target: "127.0.0.1", SourceIP: "127.0.0.1"})
			if out.Outcome != "ok" || !strings.Contains(out.Output, "127.0.0.1") {
				t.Fatalf("%s: %s", out.Outcome, out.Output)
			}
		})
	}
}
