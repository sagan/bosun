package spec

import "testing"

func TestDiagnosticValidation(t *testing.T) {
	for _, r := range []DiagnosticRequest{
		{Type: "dns", Target: "example.com", Resolver: "[2001:db8::53]:5353"},
		{Type: "dns", Target: "example.com", Resolver: "192.0.2.53"},
		{Type: "tcp", Target: "[2001:db8::1]:443"},
		{Type: "http", Target: "https://example.com:8443/health?a=1"},
		{Type: "download", Target: "http://10.10.0.2/test"},
		{Type: "mtr", Target: "example.com.", SourceIP: "10.10.0.2"},
		{Type: "traceroute", Target: "2001:db8::1"},
	} {
		if err := r.Validate(); err != nil {
			t.Fatalf("valid %+v: %v", r, err)
		}
	}
	for _, r := range []DiagnosticRequest{
		{Type: "mtr", Target: "--help"}, {Type: "mtr", Target: "example.com;id"},
		{Type: "mtr", Target: "example.com\n--report"}, {Type: "mtr", Target: "$(id)"},
		{Type: "dns", Target: "127.0.0.1"}, {Type: "dns", Target: "example.com", Resolver: "example.com:53"},
		{Type: "dns", Target: "example.com", Resolver: "192.0.2.53:0"},
		{Type: "tcp", Target: "example.com"}, {Type: "tcp", Target: "example.com:http"},
		{Type: "tcp", Target: "example.com:65536"}, {Type: "tcp", Target: "example.com:443", SourceIP: "-I eth0"},
		{Type: "http", Target: "file:///etc/passwd"}, {Type: "http", Target: "https://user:pass@example.com"},
		{Type: "http", Target: "https://example.com:0"}, {Type: "http", Target: "https://example.com/#fragment"},
		{Type: "http", Target: "https://example.com/\n"}, {Type: "http", Target: "https://example.com", Resolver: "192.0.2.53"},
		{Type: "shell", Target: "id"},
	} {
		if err := r.Validate(); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
