// Package netdiag runs a fixed set of bounded network checks, never a shell.
package netdiag

import (
	"context"
	"errors"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/zeptop-dev/bosun/internal/probe"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

const MaxDuration = 35 * time.Second
const MaxOutput = 32 << 10

// Default is shared by the Captain driver and the local UI. Only one check can
// run on a node at a time, including when both interfaces are used together.
var Default Runner

type Runner struct {
	busy atomic.Bool
}

func (r *Runner) Run(parent context.Context, in spec.DiagnosticRequest) (out spec.DiagnosticResult) {
	start := time.Now()
	out.Type, out.StartedAt = in.Type, start.Unix()
	defer func() { out.DurationMs = float64(time.Since(start)) / float64(time.Millisecond) }()
	if in.Validate() != nil {
		out.Outcome = "invalid"
		return
	}
	if !r.busy.CompareAndSwap(false, true) {
		out.Outcome = "busy"
		return
	}
	defer r.busy.Store(false)
	ctx, cancel := context.WithTimeout(parent, MaxDuration)
	defer cancel()
	switch in.Type {
	case "dns":
		resolver := &net.Resolver{PreferGo: true}
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			if in.Resolver != "" {
				address = in.Resolver
				if net.ParseIP(address) != nil {
					address = net.JoinHostPort(address, "53")
				}
			}
			d := net.Dialer{Timeout: 3 * time.Second}
			if in.SourceIP != "" {
				if strings.HasPrefix(network, "tcp") {
					d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(in.SourceIP)}
				} else {
					d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(in.SourceIP)}
				}
			}
			return d.DialContext(ctx, network, address)
		}
		dctx, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		ips, err := resolver.LookupIP(dctx, "ip", in.Target)
		out.Outcome = "ok"
		if err != nil || len(ips) == 0 {
			out.Outcome = "dns"
			if dctx.Err() != nil {
				out.Outcome = contextOutcome(dctx.Err())
			}
		}
		for _, ip := range ips {
			if len(out.Addresses) == 64 {
				break
			}
			out.Addresses = append(out.Addresses, ip.String())
		}
	case "tcp", "http", "download":
		m := new(probe.Runner).MeasureOnce(ctx, spec.PingTask{Type: in.Type, Target: in.Target, SourceIP: in.SourceIP})
		out.Measurement, out.Outcome = &m, m.Outcome
	case "mtr", "traceroute":
		path, err := exec.LookPath(in.Type)
		if err != nil {
			out.Outcome = "unavailable"
			return
		}
		family := "ip"
		if src := net.ParseIP(in.SourceIP); src != nil {
			family = "ip6"
			if src.To4() != nil {
				family = "ip4"
			}
		}
		dctx, stop := context.WithTimeout(ctx, 5*time.Second)
		ips, err := net.DefaultResolver.LookupIP(dctx, family, in.Target)
		stop()
		if err != nil || len(ips) == 0 {
			out.Outcome = "dns"
			return
		}
		out.Addresses = []string{ips[0].String()}
		cmd := exec.CommandContext(ctx, path, routeArgs(in, ips[0])...)
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		cmd.WaitDelay = time.Second
		b := &boundedOutput{}
		cmd.Stdout, cmd.Stderr = b, b
		err = cmd.Run()
		out.Output, out.Truncated = b.text(), b.truncated
		out.Outcome = "ok"
		if err != nil {
			out.Outcome = "failed"
		}
	}
	if ctx.Err() != nil {
		out.Outcome = contextOutcome(ctx.Err())
	}
	return
}

func contextOutcome(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "timeout"
}

func routeArgs(in spec.DiagnosticRequest, ip net.IP) []string {
	family := "-6"
	if ip.To4() != nil {
		family = "-4"
	}
	args := []string{family, "-n", "-m", "20"}
	if in.Type == "mtr" {
		args = append(args, "-r", "-c", "5", "-i", "0.2")
		if in.SourceIP != "" {
			args = append(args, "-a", in.SourceIP)
		}
	} else {
		args = append(args, "-q", "1", "-w", "1")
		if in.SourceIP != "" {
			args = append(args, "-s", in.SourceIP)
		}
	}
	// DNS is resolved first: the final argument can never become a flag.
	return append(args, ip.String())
}

type boundedOutput struct {
	data      []byte
	truncated bool
}

var _ io.Writer = (*boundedOutput)(nil)

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := min(len(p), MaxOutput-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.truncated = b.truncated || n < len(p)
	return len(p), nil
}
func (b *boundedOutput) text() string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, strings.ToValidUTF8(string(b.data), ""))
}
