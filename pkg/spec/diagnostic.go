package spec

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const NetworkDiagnosticKind = "network_diagnostic"
const DiagnosticTTLSeconds = 120

// DiagnosticRequest describes one bounded, administrator-initiated check.
// It deliberately has no command, flags, headers or request body fields.
type DiagnosticRequest struct {
	Type     string `json:"type"`
	Services bool   `json:"services,omitempty"`
	Target   string `json:"target"`
	SourceIP string `json:"source_ip,omitempty"`
	Resolver string `json:"resolver,omitempty"` // DNS only: literal IP, optional port
}

type DiagnosticParams struct {
	DiagnosticRequest
	ExpiresAt int64 `json:"expires_at"`
}

type DiagnosticResult struct {
	Type        string            `json:"type"`
	Exit        json.RawMessage   `json:"exit,omitempty"`
	StartedAt   int64             `json:"started_at"`
	DurationMs  float64           `json:"duration_ms"`
	Outcome     string            `json:"outcome"`
	Addresses   []string          `json:"addresses,omitempty"`
	Measurement *ProbeMeasurement `json:"measurement,omitempty"`
	Output      string            `json:"output,omitempty"` // plain text; never HTML
	Truncated   bool              `json:"truncated,omitempty"`
}

func diagnosticHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func diagnosticPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func (r DiagnosticRequest) Validate() error {
	if r.SourceIP != "" && net.ParseIP(r.SourceIP) == nil {
		return fmt.Errorf("source must be an IP")
	}
	if r.Resolver != "" {
		host, port, err := net.SplitHostPort(r.Resolver)
		if r.Type != "dns" || (net.ParseIP(r.Resolver) == nil && (err != nil || net.ParseIP(host) == nil || !diagnosticPort(port))) {
			return fmt.Errorf("DNS resolver must be an IP with an optional port")
		}
	}
	if r.Services && r.Type != "exit" {
		return fmt.Errorf("service checks are only valid for exit diagnostics")
	}
	switch r.Type {
	case "exit":
		if r.Target != "" || r.Resolver != "" {
			return fmt.Errorf("exit diagnostics use fixed providers; no target or resolver is accepted")
		}
	case "dns", "mtr", "traceroute":
		if !diagnosticHost(r.Target) || (r.Type == "dns" && net.ParseIP(r.Target) != nil) {
			return fmt.Errorf("target must be a hostname (or an IP for route checks)")
		}
	case "tcp":
		host, port, err := net.SplitHostPort(r.Target)
		if err != nil || !diagnosticHost(host) || !diagnosticPort(port) {
			return fmt.Errorf("TCP target must be host:port with a numeric port")
		}
	case "http", "download":
		u, err := url.Parse(r.Target)
		if err != nil || len(r.Target) > 2048 || !Plain(r.Target) || strings.ContainsAny(r.Target, " \t\"'") || (u.Scheme != "http" && u.Scheme != "https") || !diagnosticHost(u.Hostname()) || u.User != nil || u.Fragment != "" || (u.Port() != "" && !diagnosticPort(u.Port())) {
			return fmt.Errorf("target must be an HTTP(S) URL without credentials or a fragment")
		}
	default:
		return fmt.Errorf("type must be dns, tcp, http, download, mtr, traceroute or exit")
	}
	return nil
}
