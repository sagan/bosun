package dns

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
)

// ObservePublicAddresses requires agreement from independent HTTPS responders.
// Force each address family and bypass environment proxies: a configured HTTP
// proxy is not this machine's public egress. Failed probes never erase an IP.
func ObservePublicAddresses(ctx context.Context) agentproto.PublicAddresses {
	out := agentproto.PublicAddresses{}
	var wg sync.WaitGroup
	for _, v6 := range []bool{false, true} {
		wg.Add(1)
		go func(v6 bool) {
			defer wg.Done()
			network, urls := "tcp4", []string{"https://api.ipify.org", "https://ipv4.icanhazip.com"}
			if v6 {
				network, urls = "tcp6", []string{"https://api6.ipify.org", "https://ipv6.icanhazip.com"}
			}
			tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, addr)
			}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			value := observeFamily(ctx, client, urls, v6)
			if v6 {
				out.IPv6 = value
			} else {
				out.IPv4 = value
			}
		}(v6)
	}
	wg.Wait()
	out.SampledAt = time.Now().Unix()
	return out
}

func observeFamily(ctx context.Context, client *http.Client, urls []string, v6 bool) string {
	value := ""
	if len(urls) < 2 {
		return ""
	}
	for _, url := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return ""
		}
		resp, err := client.Do(req)
		if err != nil {
			return ""
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		resp.Body.Close()
		candidate := strings.TrimSpace(string(raw))
		if err != nil || resp.StatusCode != http.StatusOK || !agentproto.ValidPublicAddress(candidate, v6) {
			return ""
		}
		candidate = net.ParseIP(candidate).String()
		if value != "" && value != candidate {
			return ""
		}
		value = candidate
	}
	return value
}
