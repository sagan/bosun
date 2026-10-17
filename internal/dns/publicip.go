package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"
)

// publicIPs asks a few well-known responders for this host's public
// addresses; "" when unknown.
var (
	ipv4Sources = []string{"https://api.ipify.org", "https://ipv4.icanhazip.com", "http://ipv4.ip.sb"}
	ipv6Sources = []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
	ipv4Re      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Re      = regexp.MustCompile(`[0-9a-fA-F]*:[0-9a-fA-F:]+`)
)

// PublicIPSources overrides the responders (tests).
var PublicIPSources = func() ([]string, []string) { return ipv4Sources, ipv6Sources }

// DetectPublicIPs returns the node's public IPv4 and IPv6 ("" when absent).
func DetectPublicIPs(ctx context.Context) (string, string) {
	return publicIPs(ctx, &http.Client{Timeout: 8 * time.Second})
}

func publicIPs(ctx context.Context, client *http.Client) (string, string) {
	v4s, v6s := PublicIPSources()
	fetch := func(urls []string, re *regexp.Regexp, want func(net.IP) bool) string {
		for _, u := range urls {
			fctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			req, err := http.NewRequestWithContext(fctx, http.MethodGet, u, nil)
			if err != nil {
				cancel()
				continue
			}
			req.Header.Set("User-Agent", "curl/8.0.1")
			resp, err := client.Do(req)
			if err != nil {
				cancel()
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			cancel()
			if m := re.FindString(string(body)); m != "" {
				if ip := net.ParseIP(m); ip != nil && want(ip) {
					return ip.String()
				}
			}
		}
		return ""
	}
	v4 := fetch(v4s, ipv4Re, func(ip net.IP) bool { return ip.To4() != nil })
	v6 := fetch(v6s, ipv6Re, func(ip net.IP) bool { return ip.To4() == nil })
	return v4, v6
}
