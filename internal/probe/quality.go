package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	probing "github.com/prometheus-community/pro-bing"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func millis(d time.Duration) float64    { return float64(d) / float64(time.Millisecond) }
func duration(start time.Time) *float64 { v := millis(time.Since(start)); return &v }

// MeasureOnce uses the same timing and success rules as scheduled probes,
// without changing their history or their reporting queue.
func (r *Runner) MeasureOnce(ctx context.Context, t spec.PingTask) spec.ProbeMeasurement {
	m := r.scheduled(ctx, t, false)
	m.Sequence = 1
	return m
}
func outcome(err error) string {
	if err == nil {
		return "ok"
	}
	var dns *net.DNSError
	var timeout net.Error
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &cert), errors.As(err, &unknown):
		return "tls"
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return "permission"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	}
	return "io"
}

// scheduled measures exactly once. Measure retains the external Komari task
// compatibility policy; periodic monitoring must not hide slow/failed attempts.
func (r *Runner) scheduled(ctx context.Context, t spec.PingTask, reachability bool) spec.ProbeMeasurement {
	start := time.Now()
	m := spec.ProbeMeasurement{LatencyMs: -1, Outcome: "invalid"}
	if t.Validate() == nil {
		switch strings.ToLower(t.Type) {
		case "tcp":
			m = r.tcpQuality(ctx, t, reachability)
		case "icmp":
			m = icmpQuality(ctx, t)
		case "http", "download":
			m = r.httpQuality(ctx, t)
		}
	}
	m.At = time.Now().Unix()
	m.DurationMs = millis(time.Since(start))
	return m
}
func (r *Runner) tcpQuality(ctx context.Context, t spec.PingTask, reachability bool) spec.ProbeMeasurement {
	m := spec.ProbeMeasurement{LatencyMs: -1, Timings: &spec.ProbeTimings{}}
	addr := t.Target
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "80")
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	var elapsed time.Duration
	var err error
	if t.SourceIP != "" && r.DialFrom != nil {
		elapsed, err = r.DialFrom(ctx, t.SourceIP, addr)
	} else if r.Dial != nil {
		elapsed, err = r.Dial(ctx, addr)
	} else {
		host, port, _ := net.SplitHostPort(addr)
		start := time.Now()
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e == nil && net.ParseIP(host) == nil {
			m.Timings.DNS = duration(start)
		}
		if e != nil || len(ips) == 0 {
			m.Outcome = "dns"
			return m
		}
		// Sequential attempts use the same deadline, including DNS. A different
		// address is only tried after a connection failure, not to improve an RTT.
		d := net.Dialer{}
		if t.SourceIP != "" {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.SourceIP)}
		}
		for _, ip := range ips {
			start = time.Now()
			var c net.Conn
			c, err = d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			elapsed = time.Since(start)
			if err == nil {
				c.Close()
				break
			}
			if reachability && errors.Is(err, syscall.ECONNREFUSED) {
				break
			}
		}
	}
	m.Outcome = outcome(err)
	if err == nil || (reachability && m.Outcome == "refused") {
		v := millis(elapsed)
		m.LatencyMs = v
		m.Timings.Connect = &v
	}
	return m
}

func icmpQuality(ctx context.Context, t spec.PingTask) spec.ProbeMeasurement {
	m := spec.ProbeMeasurement{LatencyMs: -1, Timings: &spec.ProbeTimings{}}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	start := time.Now()
	network := "ip"
	if source := net.ParseIP(t.SourceIP); source != nil {
		network = "ip6"
		if source.To4() != nil {
			network = "ip4"
		}
	}
	// A source-bound check must choose a destination of the same family, even
	// when DNS puts the other family first.
	ips, err := net.DefaultResolver.LookupIP(ctx, network, t.Target)
	if err == nil && net.ParseIP(t.Target) == nil {
		m.Timings.DNS = duration(start)
	}
	if err != nil || len(ips) == 0 {
		m.Outcome = "dns"
		return m
	}
	p := probing.New(ips[0].String())
	p.Count = 1
	p.Timeout = dialTimeout
	p.Source = t.SourceIP
	p.SetPrivileged(true)
	err = p.RunWithContext(ctx)
	// Changing the socket mode is not a second network attempt: retry only when
	// the privileged socket could not be opened, never after an ICMP timeout.
	if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
		p.SetPrivileged(false)
		err = p.RunWithContext(ctx)
	}
	if err != nil {
		m.Outcome = outcome(err)
		return m
	}
	st := p.Statistics()
	if st == nil || st.PacketsRecv == 0 {
		m.Outcome = "timeout"
		return m
	}
	m.LatencyMs = millis(st.AvgRtt)
	m.Outcome = "ok"
	return m
}

type httpPhases struct {
	mu              sync.Mutex
	dns, tls, wrote time.Time
	connects        map[string]time.Time
	connected       map[string]float64
	times           spec.ProbeTimings
	tlsFailed       bool
}

func (p *httpPhases) trace() *httptrace.ClientTrace {
	p.connects = map[string]time.Time{}
	p.connected = map[string]float64{}
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { p.mu.Lock(); defer p.mu.Unlock(); p.dns = time.Now() },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if i.Err == nil && !p.dns.IsZero() {
				p.times.DNS = duration(p.dns)
			}
		},
		ConnectStart: func(_, addr string) { p.mu.Lock(); defer p.mu.Unlock(); p.connects[addr] = time.Now() },
		ConnectDone: func(_, addr string, err error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if start, ok := p.connects[addr]; ok && err == nil {
				p.connected[addr] = millis(time.Since(start))
				x := p.connected[addr]
				p.times.Connect = &x
			}
		},
		GotConn: func(i httptrace.GotConnInfo) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if v, ok := p.connected[i.Conn.RemoteAddr().String()]; ok {
				x := v
				p.times.Connect = &x
			}
		},
		TLSHandshakeStart: func() { p.mu.Lock(); defer p.mu.Unlock(); p.tls = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.tlsFailed = err != nil
			if err == nil && !p.tls.IsZero() {
				p.times.TLS = duration(p.tls)
			}
		},
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if i.Err == nil {
				p.wrote = time.Now()
			}
		},
		GotFirstResponseByte: func() {
			p.mu.Lock()
			defer p.mu.Unlock()
			if !p.wrote.IsZero() {
				p.times.Response = duration(p.wrote)
			}
		},
	}
}
func (r *Runner) httpQuality(parent context.Context, t spec.PingTask) (m spec.ProbeMeasurement) {
	m.LatencyMs = -1
	download := strings.EqualFold(t.Type, "download")
	if download && r.Download != nil {
		m.LatencyMs, m.Mbps = r.Download(parent, t.Target)
		m.Outcome = "ok"
		if m.LatencyMs < 0 {
			m.Outcome = "io"
		}
		return
	}
	span := dialTimeout
	if download {
		span = downloadWindow + 5*time.Second
	}
	ctx, cancel := context.WithTimeout(parent, span)
	defer cancel()
	var phases httpPhases
	ctx = httptrace.WithClientTrace(ctx, phases.trace())
	target := t.Target
	if !strings.Contains(target, "://") {
		target = "https://" + target
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		m.Outcome = "invalid"
		return
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	if t.SourceIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(t.SourceIP)}
	}
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, TLSHandshakeTimeout: dialTimeout, ResponseHeaderTimeout: dialTimeout, DialContext: dialer.DialContext}
	if r.HTTPTransport != nil {
		transport = r.HTTPTransport.Clone()
		transport.DisableKeepAlives = true
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	start := time.Now()
	resp, err := client.Do(req)
	ttfb := millis(time.Since(start))
	phases.mu.Lock()
	times := phases.times
	m.Timings = &times
	tlsFailed := phases.tlsFailed
	phases.mu.Unlock()
	if err != nil {
		m.Outcome = outcome(err)
		if tlsFailed && m.Outcome != "timeout" && m.Outcome != "canceled" {
			m.Outcome = "tls"
		}
		return
	}
	defer resp.Body.Close()
	m.HTTPStatus = resp.StatusCode
	if resp.StatusCode < 200 || resp.StatusCode >= 400 || (download && resp.StatusCode >= 300) {
		m.Outcome = "http_status"
		return
	}
	m.LatencyMs = ttfb
	m.Outcome = "ok"
	if !download {
		return
	}
	// Bound duration and bytes independently, including a server that stalls its
	// response body. Timed completion is success only if some data arrived.
	timer := time.AfterFunc(downloadWindow, cancel)
	defer timer.Stop()
	transferStart := time.Now()
	n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<20))
	m.Bytes = n
	plannedEnd := time.Since(transferStart) >= downloadWindow && parent.Err() == nil
	if readErr != nil && !plannedEnd {
		m.Outcome = outcome(readErr)
		m.LatencyMs = -1
		return
	}
	if n == 0 {
		m.Outcome = "empty"
		m.LatencyMs = -1
		return
	}
	m.Mbps = float64(n) * 8 / time.Since(transferStart).Seconds() / 1e6
	return
}

func windowStats(samples []spec.ProbeMeasurement) spec.ProbeWindow {
	if len(samples) > ringSize {
		samples = samples[len(samples)-ringSize:]
	}
	w := spec.ProbeWindow{Attempts: len(samples)}
	values := []float64{}
	jitter := 0.0
	pairs := 0
	for i, m := range samples {
		if m.LatencyMs < 0 {
			w.Failed++
			continue
		}
		values = append(values, m.LatencyMs)
		if i > 0 && samples[i-1].LatencyMs >= 0 {
			jitter += math.Abs(m.LatencyMs - samples[i-1].LatencyMs)
			pairs++
		}
	}
	if len(values) > 0 {
		sort.Float64s(values)
		min, max, p50, p95 := values[0], values[len(values)-1], values[int(math.Ceil(float64(len(values))*.5))-1], values[int(math.Ceil(float64(len(values))*.95))-1]
		w.Min = &min
		w.Max = &max
		w.P50 = &p50
		w.P95 = &p95
	}
	if pairs > 0 {
		v := jitter / float64(pairs)
		w.Jitter = &v
	}
	return w
}
