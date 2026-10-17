package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectPublicIPs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v4" {
			_, _ = w.Write([]byte("192.0.2.10\n"))
		} else {
			_, _ = w.Write([]byte("2001:db8::10\n"))
		}
	}))
	defer srv.Close()
	old := PublicIPSources
	PublicIPSources = func() ([]string, []string) { return []string{srv.URL + "/v4"}, []string{srv.URL + "/v6"} }
	defer func() { PublicIPSources = old }()
	v4, v6 := DetectPublicIPs(context.Background())
	if v4 != "192.0.2.10" || v6 != "2001:db8::10" {
		t.Fatalf("addresses: %q %q", v4, v6)
	}
}
