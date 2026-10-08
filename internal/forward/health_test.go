package forward

import (
	"context"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"log/slog"
	"testing"
	"time"
)

func TestUDPHealthDoesNotUseTCP(t *testing.T) {
	target := udpEcho(t)
	for _, backend := range []string{"", "nft", "realm"} {
		t.Run(backend, func(t *testing.T) {
			f := spec.Forward{Tag: "udp", Target: target, Protocol: "udp", Backend: backend, Listen: "127.0.0.1", Port: freePort(t)}
			var r *rule
			var err error
			if backend == "" {
				r, err = start(f, slog.Default())
				if err != nil {
					t.Fatal(err)
				}
			} else {
				r = startProbeOnly(f, slog.Default())
			}
			defer r.stop()
			m := NewManager(slog.Default())
			m.rules["r"] = r
			r.probe(context.Background())
			s := m.Snapshot()[0].Status()
			if s.Health != "unknown" || s.ProbeProtocol != "none" || s.LastError != "" {
				t.Fatalf("UDP incorrectly measured: %+v", s)
			}
			r.setBackend(errors.New("backend unavailable"))
			r.probe(context.Background())
			if s = m.Snapshot()[0].Status(); s.Health != "down" || s.ProbeProtocol != "backend" {
				t.Fatal(s)
			}
			r.setBackend(nil)
			if s = m.Snapshot()[0].Status(); s.Health != "unknown" || s.LastError != "" {
				t.Fatal("stale failure", s)
			}
		})
	}
}
func TestMixedForwardUDPSelectionIgnoresTCPFailure(t *testing.T) {
	target := udpEcho(t)
	for _, balance := range []string{"failover", "roundrobin"} {
		t.Run(balance, func(t *testing.T) {
			f := spec.Forward{Tag: "mixed", Target: target, Protocol: "both", Balance: balance, Targets: []spec.ForwardTarget{{Target: udpEcho(t)}}}
			r := startProbeOnly(f, slog.Default())
			defer r.stop()
			r.hops[0].set(false, 0, errors.New("TCP refused"))
			r.hops[1].set(true, time.Millisecond, nil)
			if r.candidates()[0] != r.hops[1] {
				t.Fatal("TCP must prefer the tested hop")
			}
			// Reset only round-robin scheduling, not the failed TCP measurement.
			for _, h := range r.hops {
				h.current = 0
			}
			conn, hop := r.dialUDP()
			if conn == nil {
				t.Fatal("no UDP socket")
			}
			defer conn.Close()
			if hop != r.hops[0] {
				t.Fatal("TCP failure changed UDP selection")
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write([]byte("ok"))
			buf := make([]byte, 2)
			if n, err := conn.Read(buf); err != nil || n != 2 || string(buf) != "ok" {
				t.Fatalf("UDP relay failed: %d %v", n, err)
			}
			// Opening or using a UDP socket must not declare the failed TCP probe healthy.
			if hop.health() != "down" {
				t.Fatal("UDP altered TCP health")
			}
		})
	}
}
func TestTCPHealthStartsUnknownThenMeasures(t *testing.T) {
	r := startProbeOnly(spec.Forward{Tag: "tcp", Target: tcpEcho(t), Protocol: "tcp"}, slog.Default())
	defer r.stop()
	if r.hops[0].health() != "unknown" {
		t.Fatal("untested hop claimed healthy")
	}
	if !r.probe(context.Background()) || r.hops[0].health() != "up" {
		t.Fatal("TCP probe failed")
	}
}
