package dns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObserveFamilyConsensusAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		status     int
		v6         bool
		want       string
	}{
		{"agree4", "192.0.2.10\n", "192.0.2.10", 200, false, "192.0.2.10"},
		{"agree6", "2001:db8::10", "2001:db8:0::10", 200, true, "2001:db8::10"},
		{"disagree", "192.0.2.10", "198.51.100.20", 200, false, ""},
		{"error body", "192.0.2.10", "192.0.2.10", 503, false, ""},
		{"private", "10.10.0.2", "10.10.0.2", 200, false, ""},
		{"wrong family", "192.0.2.10", "192.0.2.10", 200, true, ""},
		{"html is not observation", "<p>192.0.2.10</p>", "192.0.2.10", 200, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if r.URL.Path == "/a" {
					_, _ = w.Write([]byte(tc.a))
				} else {
					_, _ = w.Write([]byte(tc.b))
				}
			}))
			defer srv.Close()
			if got := observeFamily(context.Background(), srv.Client(), []string{srv.URL + "/a", srv.URL + "/b"}, tc.v6); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
