package netdiag

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestRouteParsingAndClassification(t *testing.T) {
	hops := parseRouteHops("traceroute to 192.0.2.30, 30 hops max\n1 10.10.0.2 0.5 ms\n2 *\n3 192.0.2.20 1.2 ms\n3 192.0.2.99 2 ms\n31 192.0.2.40 3 ms\n")
	if len(hops) != 3 || hops[1].IP != "" || hops[0].RTT == nil || *hops[0].RTT != 0.5 {
		t.Fatalf("%+v", hops)
	}
	for _, tc := range []struct {
		name string
		asns []uint32
		want string
	}{
		{"single CN2", []uint32{4809}, "cn2"},
		{"multiple CN2", []uint32{4809, 4809}, "possible_gia"},
		{"mixed CN2", []uint32{4809, 4134}, "mixed"},
		{"mixed unicom", []uint32{9929, 4837}, "mixed"},
		{"mixed mobile", []uint32{58807, 58453}, "mixed"},
		{"only mobile domestic", []uint32{9808}, "observed"},
		{"unknown", []uint32{64500}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := spec.RoutePath{Target: "192.0.2.30", Reached: true, Outcome: "ok"}
			for i, asn := range tc.asns {
				p.Hops = append(p.Hops, spec.RouteHop{TTL: i + 1, IP: fmt.Sprintf("192.0.2.%d", i+1), ASNs: []uint32{asn}})
			}
			p.Hops = append(p.Hops, spec.RouteHop{TTL: len(p.Hops) + 1, IP: p.Target, ASNs: []uint32{4134}})
			classifyRoute(&p)
			if p.Classification != tc.want {
				t.Fatalf("%s: %+v", tc.want, p)
			}
			if tc.want == "possible_gia" {
				p.Hops[0].IP = ""
				classifyRoute(&p)
				if p.Classification == "possible_gia" {
					t.Fatal("missing hop implied GIA")
				}
			}
		})
	}
	p := spec.RoutePath{Target: "192.0.2.30", Hops: []spec.RouteHop{{TTL: 1, IP: "192.0.2.30", ASNs: []uint32{9929}}}}
	classifyRoute(&p)
	if p.Classification != "unknown" {
		t.Fatal("destination classified as transit")
	}
}
func TestRouteASNQueries(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.10")
	if asnQuery(ip) != "10.2.0.192.origin.asn.cymru.com" {
		t.Fatal(asnQuery(ip))
	}
	q := asnQuery(netip.MustParseAddr("2001:db8::1"))
	if !strings.HasPrefix(q, "1.0.0.0.") || !strings.HasSuffix(q, "8.b.d.0.1.0.0.2.origin6.asn.cymru.com") {
		t.Fatal(q)
	}
	got := parseASNs([]string{"4809 4134 | 192.0.2.0/24 | ZZ", "9929 | 198.51.100.0/24", "garbage", "0 4294967296 | 192.0.2.0/24"}, ip)
	if !reflect.DeepEqual(got, []uint32{4134, 4809}) {
		t.Fatal(got)
	}
	for _, s := range []string{"10.10.0.2", "127.0.0.1", "169.254.169.254", "100.64.0.1", "fc00::1", "fe80::1"} {
		if publicRouteIP(netip.MustParseAddr(s)) {
			t.Fatal("private leak", s)
		}
	}
}
func TestRouteCollectorKeepsPartialPathsWithoutASN(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traceroute")
	// Private-hop fixture cannot trigger an external ASN request.
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf 'traceroute header\\n1 10.10.0.2 0.5 ms\\n2 *\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, status := collectReturnRoutes(ctx, spec.ReturnRouteRequest{City: "beijing", Family: "ipv4"}, path, func(context.Context, string) ([]string, error) {
		t.Error("private IP sent to ASN provider")
		return nil, errors.New("offline")
	})
	if status != "incomplete" || len(out.Paths) != 3 {
		t.Fatalf("%s %+v", status, out)
	}
	for _, p := range out.Paths {
		if p.Reached || p.Classification != "unknown" || len(p.Hops) != 2 {
			t.Fatalf("%+v", p)
		}
	}
}

func TestRouteASNFailureAndFamilyIsolation(t *testing.T) {
	// Use the public target only as canned traceroute output; the executable
	// sends no packets and the injected DNS function performs no network I/O.
	target := routeTargets["beijing"][0][0]
	path := filepath.Join(t.TempDir(), "traceroute")
	script := "#!/bin/sh\nprintf '1 " + target + " 1 ms\\n2 *\\n'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var calls int
	// One unique address means one worker invokes this stub.
	lookup := func(context.Context, string) ([]string, error) { calls++; return nil, errors.New("unavailable") }
	out, _ := collectReturnRoutes(ctx, spec.ReturnRouteRequest{City: "beijing", Family: "ipv4"}, path, lookup)
	if calls != 1 {
		t.Fatal("lookup not deduplicated", calls)
	}
	for _, p := range out.Paths {
		if p.ASNMissing != 1 || p.Classification != "unknown" {
			t.Fatalf("%+v", p)
		}
	}
	calls = 0
	out, _ = collectReturnRoutes(ctx, spec.ReturnRouteRequest{City: "beijing", Family: "ipv6"}, path, lookup)
	if calls != 0 {
		t.Fatal("wrong family looked up")
	}
	for _, p := range out.Paths {
		for _, h := range p.Hops {
			if h.IP != "" {
				t.Fatal("IPv4 contaminated IPv6")
			}
		}
	}
}

func TestRouteUnreachableAndRepeatedHop(t *testing.T) {
	h := parseRouteHops("1 192.0.2.10 2 ms !H\n")
	if len(h) != 1 || h[0].Reply != "!H" {
		t.Fatal(h)
	}
	p := spec.RoutePath{Target: "192.0.2.30", Outcome: "ok", Reached: true, Hops: []spec.RouteHop{
		{TTL: 1, IP: "192.0.2.10", ASNs: []uint32{4809}},
		{TTL: 2, IP: "192.0.2.10", ASNs: []uint32{4809}},
		{TTL: 3, IP: "192.0.2.30"},
	}}
	classifyRoute(&p)
	if p.Classification != "cn2" {
		t.Fatal("repeated router inflated evidence", p)
	}
}
