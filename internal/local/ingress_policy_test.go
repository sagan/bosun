package local

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestNATIngressPolicy(t *testing.T) {
	s := openTest(t)
	g, err := s.PutIngress(Ingress{Name: "NAT", Kind: "nat", BindIP: "10.10.0.2", EntryHost: "203.0.113.30", RequireIngress: true, PortMappings: []spec.PortMapping{{LocalFrom: 20000, LocalTo: 20009, PublicFrom: 30000}, {LocalFrom: 40000, LocalTo: 40000, PublicFrom: 443}}, ReservedPorts: []int{20000}}, "")
	if err != nil {
		t.Fatal(err)
	}
	ib := Inbound{Inbound: spec.Inbound{Tag: "m", Protocol: spec.Mieru, Port: 20001}, Enabled: true, IngressID: g.ID}
	for _, id := range []string{"", "missing"} {
		x := ib
		x.IngressID = id
		if s.PutInbound(x, "") == nil {
			t.Fatal("inbound bypassed ingress", id)
		}
	}
	if err := s.PutInbound(ib, ""); err != nil {
		t.Fatal(err)
	}
	f := spec.Forward{Tag: "relay", Port: 20002, Protocol: "both", Target: "198.51.100.20:443", IngressID: g.ID}
	for _, id := range []string{"", "missing"} {
		x := f
		x.IngressID = id
		if s.PutForward(x, "") == nil {
			t.Fatal("forward bypassed ingress", id)
		}
	}
	for _, port := range []int{20000, 20010} {
		x := f
		x.Port = port
		if s.PutForward(x, "") == nil {
			t.Fatal("forward bypassed ports", port)
		}
	}
	for _, backend := range []string{"", "nft", "realm"} {
		f.Backend = backend
		if err := s.PutForward(f, func() string {
			if backend == "" {
				return ""
			}
			return f.Tag
		}()); err != nil {
			t.Fatal(err)
		}
	}
	bad := g
	bad.PortMappings = []spec.PortMapping{{LocalFrom: 40000, LocalTo: 40000, PublicFrom: 443}}
	if _, err := s.PutIngress(bad, g.ID); err == nil {
		t.Fatal("invalidated an existing listener")
	}
	bad = g
	bad.ReservedPorts = []int{20002}
	if _, err := s.PutIngress(bad, g.ID); err == nil {
		t.Fatal("reserved existing forward")
	}
	if err := s.DeleteIngress(g.ID); err == nil {
		t.Fatal("deleted used ingress")
	}
	// Persistence and runtime resolution are independent of editor metadata.
	s, _, err = Open(s.path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	gs := s.ListIngresses()
	if len(gs) != 1 || !gs[0].RequireIngress || gs[0].EntryPort(40000) != 443 {
		t.Fatal("policy lost on restart", gs)
	}
	fs, _, err := s.Forwards(context.Background())
	if err != nil || len(fs) != 1 || fs[0].Listen != "10.10.0.2" || fs[0].Port != 20002 || fs[0].IngressID != "" {
		t.Fatal("unresolved forward", fs, err)
	}
	n, _, err := s.Node(context.Background())
	if err != nil || n.Inbounds[0].Listen != "10.10.0.2" || n.Forwards[0].Listen != "10.10.0.2" {
		t.Fatal("unresolved node", n, err)
	}
}

func TestRequireIngressChecksExistingDirectListeners(t *testing.T) {
	s := openTest(t)
	if err := s.PutForward(spec.Forward{Tag: "direct", Port: 20001, Target: "198.51.100.20:443"}, ""); err != nil {
		t.Fatal(err)
	}
	g := Ingress{Name: "NAT", Kind: "nat", EntryHost: "203.0.113.30", PortFrom: 20000, PortTo: 20099, RequireIngress: true}
	if _, err := s.PutIngress(g, ""); err == nil {
		t.Fatal("enabled restrictions over direct forward")
	}
	if len(s.ListIngresses()) != 0 {
		t.Fatal("failed edit persisted")
	}
}
