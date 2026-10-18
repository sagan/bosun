package netdiag

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Public measurement endpoints, not operator infrastructure. Catalog reference:
// https://github.com/oneclickvirt/backtrace/blob/main/model/model.go
// Snapshot 2026-10-17. Never silently replace targets during a measurement.
var routeTargets = map[string][2][3]string{
	"beijing":   {{"219.141.140.10", "202.106.195.68", "221.179.155.161"}, {"2400:89c0:1053:3::69", "2400:89c0:1013:3::54", "2409:8c00:8421:1303::55"}},
	"shanghai":  {{"202.96.209.133", "210.22.97.1", "211.136.112.200"}, {"240e:e1:aa00:4000::24", "2408:80f1:21:5003::a", "2409:8c1e:75b0:3003::26"}},
	"guangzhou": {{"58.60.188.222", "210.21.196.6", "120.196.165.24"}, {"240e:97c:2f:3000::44", "2408:8756:f50:1001::c", "2409:8c54:871:1001::12"}},
}

func runReturnRoute(ctx context.Context, req spec.ReturnRouteRequest) (*spec.ReturnRouteResult, string) {
	if runtime.GOOS != "linux" {
		return &spec.ReturnRouteResult{City: req.City, Family: req.Family}, "unavailable"
	}
	path, err := exec.LookPath("traceroute")
	if err != nil {
		return &spec.ReturnRouteResult{City: req.City, Family: req.Family}, "unavailable"
	}
	return collectReturnRoutes(ctx, req, path, net.DefaultResolver.LookupTXT)
}

func collectReturnRoutes(ctx context.Context, req spec.ReturnRouteRequest, path string, lookup func(context.Context, string) ([]string, error)) (*spec.ReturnRouteResult, string) {
	out := &spec.ReturnRouteResult{City: req.City, Family: req.Family, Engine: "traceroute", Protocol: "icmp", RulesVersion: "1", ASNProvider: "Team Cymru DNS"}
	family, index := "-4", 0
	if req.Family == "ipv6" {
		family, index = "-6", 1
	}
	targets := routeTargets[req.City][index]
	carriers := []string{"telecom", "unicom", "mobile"}
	out.Paths = make([]spec.RoutePath, 3)
	var wg sync.WaitGroup
	// Three bounded subprocesses in one admitted diagnostic; none invokes a shell.
	for i, target := range targets {
		wg.Add(1)
		go func(i int, target string) {
			defer wg.Done()
			p := spec.RoutePath{Carrier: carriers[i], Target: target, Outcome: "ok", Hops: []spec.RouteHop{}, Evidence: []spec.RouteEvidence{}, Classification: "unknown"}
			tctx, cancel := context.WithTimeout(ctx, 40*time.Second)
			defer cancel()
			cmd := exec.CommandContext(tctx, path, family, "-I", "-n", "-m", "30", "-q", "1", "-w", "1", target)
			cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
			cmd.WaitDelay = time.Second
			b := &boundedOutput{}
			cmd.Stdout, cmd.Stderr = b, b
			if err := cmd.Run(); err != nil {
				p.Outcome = "failed"
			}
			if tctx.Err() != nil {
				p.Outcome = contextOutcome(tctx.Err())
			}
			if b.truncated {
				p.Outcome = "truncated"
			}
			p.Hops = parseRouteHops(b.text())
			for j := range p.Hops {
				ip, err := netip.ParseAddr(p.Hops[j].IP)
				if err == nil && ip.Is4() != (index == 0) {
					p.Hops[j].IP = ""
					p.Hops[j].RTT = nil
				}
			}
			for _, hop := range p.Hops {
				if hop.IP == target && hop.Reply == "" {
					p.Reached = true
				}
			}
			if p.Outcome == "ok" && !p.Reached {
				p.Outcome = "incomplete"
			}
			out.Paths[i] = p
		}(i, target)
	}
	wg.Wait()
	// Cache within this measurement; never leak private hops to external DNS.
	cache := map[string][]uint32{}
	for _, p := range out.Paths {
		for _, h := range p.Hops {
			ip, err := netip.ParseAddr(h.IP)
			if err == nil && publicRouteIP(ip) {
				cache[h.IP] = nil
			}
		}
	}
	work := make(chan string, len(cache))
	for ip := range cache {
		work <- ip
	}
	close(work)
	var mu sync.Mutex
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for addr := range work {
				if ctx.Err() != nil {
					return
				}
				ip := netip.MustParseAddr(addr)
				qctx, cancel := context.WithTimeout(ctx, time.Second)
				txt, _ := lookup(qctx, asnQuery(ip))
				cancel()
				asns := parseASNs(txt, ip)
				mu.Lock()
				cache[addr] = asns
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for i := range out.Paths {
		p := &out.Paths[i]
		for j := range p.Hops {
			h := &p.Hops[j]
			if asns, found := cache[h.IP]; found {
				h.ASNs = asns
				if len(asns) == 0 {
					p.ASNMissing++
				}
			}
		}
		classifyRoute(p)
	}
	if ctx.Err() != nil {
		return out, contextOutcome(ctx.Err())
	}
	for _, p := range out.Paths {
		if p.Outcome != "ok" {
			return out, "incomplete"
		}
	}
	return out, "ok"
}

// Parse numeric traceroute only. Empty hops remain explicit; never interpret
// the header's destination as a responding hop.
func parseRouteHops(raw string) []spec.RouteHop {
	out := []spec.RouteHop{}
	last := 0
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ttl, err := strconv.Atoi(f[0])
		if err != nil || ttl <= last || ttl > 30 {
			continue
		}
		h := spec.RouteHop{TTL: ttl}
		for i := 1; i < len(f); i++ {
			ip, err := netip.ParseAddr(f[i])
			if err != nil {
				continue
			}
			h.IP = ip.String()
			if i+2 < len(f) && f[i+2] == "ms" {
				if v, err := strconv.ParseFloat(f[i+1], 64); err == nil && v >= 0 && v < 60000 {
					h.RTT = &v
				}
			}
			break
		}
		for _, field := range f[1:] {
			if strings.HasPrefix(field, "!") && len(field) <= 16 {
				h.Reply = field
				break
			}
		}
		out = append(out, h)
		last = ttl
	}
	return out
}

func publicRouteIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Is4In6() {
		return false
	}
	for _, prefix := range spec.PrivateRanges {
		p, err := netip.ParsePrefix(prefix)
		if err == nil && p.Contains(ip) {
			return false
		}
	}
	return true
}
func asnQuery(ip netip.Addr) string {
	if ip.Is4() {
		a := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", a[3], a[2], a[1], a[0])
	}
	a := ip.As16()
	s := hex.EncodeToString(a[:])
	var b strings.Builder
	for i := len(s) - 1; i >= 0; i-- {
		b.WriteByte(s[i])
		b.WriteByte('.')
	}
	return b.String() + "origin6.asn.cymru.com"
}
func parseASNs(records []string, ip netip.Addr) []uint32 {
	seen := map[uint32]bool{}
	for _, txt := range records {
		parts := strings.Split(txt, "|")
		if len(parts) < 2 {
			continue
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(parts[1]))
		if err != nil || !p.Contains(ip) {
			continue
		}
		for _, field := range strings.Fields(parts[0]) {
			n, err := strconv.ParseUint(field, 10, 32)
			if err == nil && n > 0 && len(seen) < 8 {
				seen[uint32(n)] = true
			}
		}
	}
	out := []uint32{}
	for n := range seen {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Evidence describes observed transit hops, not a purchased service tier.
// The destination itself is excluded. CN2 GIA is only a hypothesis even with
// multiple CN2 hops; hidden routers and policy routing cannot be inferred.
func classifyRoute(p *spec.RoutePath) {
	evidence := map[string][]int{}
	seenIP := map[string]bool{}
	names := map[uint32]string{4809: "cn2", 4134: "163", 9929: "9929", 10099: "cug", 4837: "4837", 58807: "cmin2", 58453: "cmi", 9808: "cmnet", 23764: "ctgnet"}
	for _, h := range p.Hops {
		if h.IP == "" || h.IP == p.Target || seenIP[h.IP] {
			continue
		}
		seenIP[h.IP] = true
		seen := map[string]bool{}
		for _, asn := range h.ASNs {
			if name := names[asn]; name != "" && !seen[name] {
				evidence[name] = append(evidence[name], h.TTL)
				seen[name] = true
			}
		}
	}
	p.Evidence = []spec.RouteEvidence{}
	for code, hops := range evidence {
		p.Evidence = append(p.Evidence, spec.RouteEvidence{Code: code, Hops: hops})
	}
	sort.Slice(p.Evidence, func(i, j int) bool {
		return p.Evidence[i].Hops[0] < p.Evidence[j].Hops[0] || (p.Evidence[i].Hops[0] == p.Evidence[j].Hops[0] && p.Evidence[i].Code < p.Evidence[j].Code)
	})
	p.Classification = "unknown"
	if len(p.Evidence) == 0 {
		return
	}
	p.Classification = "observed"
	if len(evidence["cn2"]) > 0 {
		p.Classification = "cn2"
		if len(evidence["163"]) > 0 {
			p.Classification = "mixed"
		} else if len(evidence["cn2"]) >= 2 && len(evidence) == 1 && p.Reached && p.Outcome == "ok" && p.ASNMissing == 0 {
			complete := true
			for i, h := range p.Hops {
				if h.IP == "" || h.Reply != "" || h.TTL != i+1 || len(h.ASNs) > 1 {
					complete = false
				}
			}
			if complete {
				p.Classification = "possible_gia"
			}
		}
	}
	if len(evidence["9929"]) > 0 && len(evidence["4837"]) > 0 || len(evidence["cmin2"]) > 0 && len(evidence["cmi"]) > 0 {
		p.Classification = "mixed"
	}
}
