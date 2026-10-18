package netdiag

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Explicit opt-in: sends bounded ICMP probes to the public catalog and public
// hop ASN queries. Logs contain counts/codes only, never observed hop IPs.
// A private artifact is written only when the operator requests an output path.
func TestReturnRouteLive(t *testing.T) {
	if os.Getenv("BOSUN_TEST_RETURN_ROUTES") != "1" {
		t.Skip("live network checks are opt-in")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux traceroute required")
	}
	city, family := os.Getenv("BOSUN_ROUTE_CITY"), os.Getenv("BOSUN_ROUTE_FAMILY")
	if city == "" {
		city = "beijing"
	}
	if family == "" {
		family = "ipv4"
	}
	req := spec.DiagnosticRequest{Type: "return_route", Route: &spec.ReturnRouteRequest{City: city, Family: family}}
	if err := req.Validate(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 95*time.Second)
	defer cancel()
	result := new(Runner).Run(ctx, req)
	if result.Route == nil {
		t.Fatal("missing structured report")
	}
	if os.Getenv("BOSUN_ROUTE_EXPECT_UNAVAILABLE") == "1" {
		if result.Outcome != "unavailable" {
			t.Fatal("missing tool did not return unavailable")
		}
		t.Log("missing-tool behavior verified")
		return
	}
	if result.Outcome != "ok" && result.Outcome != "incomplete" {
		t.Fatalf("unexpected result %s", result.Outcome)
	}
	if len(result.Route.Paths) != 3 {
		t.Fatal("carrier results missing")
	}
	replyCount := 0
	for _, p := range result.Route.Paths {
		responses, asns := 0, 0
		for _, h := range p.Hops {
			if h.IP != "" {
				responses++
			}
			if len(h.ASNs) > 0 {
				asns++
			}
		}
		replyCount += responses
		codes := []string{}
		for _, e := range p.Evidence {
			codes = append(codes, e.Code)
		}
		t.Logf("%s %s %s: outcome=%s reached=%v replies=%d asn_hops=%d asn_missing=%d class=%s evidence=%v", city, family, p.Carrier, p.Outcome, p.Reached, responses, asns, p.ASNMissing, p.Classification, codes)
	}
	if replyCount == 0 && os.Getenv("BOSUN_ROUTE_ALLOW_NO_REPLIES") != "1" {
		t.Fatal("no real hop replies; cannot validate collection")
	}
	t.Logf("total duration %.0f ms", result.DurationMs)
	if name := os.Getenv("BOSUN_ROUTE_OUTPUT"); name != "" {
		if !filepath.IsAbs(name) {
			t.Fatal("artifact path must be absolute")
		}
		b, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := f.Write(b)
		closeErr := f.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
}

// Run only inside an explicitly isolated Linux network namespace. This proves
// real traceroute failures are not reported as a reached or classified route.
func TestReturnRouteNoNetwork(t *testing.T) {
	if os.Getenv("BOSUN_TEST_ROUTE_ISOLATED") != "1" {
		t.Skip("isolated network namespace opt-in")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux required")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 {
			t.Fatal("refusing non-isolated network")
		}
	}
	req := spec.DiagnosticRequest{Type: "return_route", Route: &spec.ReturnRouteRequest{City: "beijing", Family: "ipv4"}}
	result := new(Runner).Run(context.Background(), req)
	if result.Outcome != "incomplete" || result.Route == nil || len(result.Route.Paths) != 3 {
		t.Fatalf("unexpected result %s", result.Outcome)
	}
	for _, p := range result.Route.Paths {
		if p.Outcome != "failed" || p.Reached || len(p.Hops) != 0 || len(p.Evidence) != 0 || p.Classification != "unknown" {
			t.Fatal("no-route failure misrepresented")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result = new(Runner).Run(ctx, req)
	if result.Outcome != "canceled" {
		t.Fatal("cancellation lost", result.Outcome)
	}
	t.Log("real no-route and canceled subprocess behavior verified")
}
