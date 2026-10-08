package ui

import (
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestEgressAPIRequiresLoginAndLocalMode(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: store, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	body := map[string]any{"upstreams": []spec.EgressUpstream{{CIDR: "10.10.0.2", Protocol: "tcp", Port: 1080}}}
	if code, _ := c.do("PUT", "/api/egress", body); code != 401 {
		t.Fatal("unauthenticated policy write", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatalf("login %d %s", code, b)
	}
	if code, b := c.do("PUT", "/api/egress", body); code != 200 || !strings.Contains(string(b), "10.10.0.2") {
		t.Fatalf("save %d %s", code, b)
	}
	if code, _ := c.do("PUT", "/api/egress", map[string]any{}); code != 400 {
		t.Fatal("omitted field cleared policy", code)
	}
	if len(store.EgressUpstreams()) != 1 {
		t.Fatal("policy erased")
	}
	if err := store.Adopt("https://example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("PUT", "/api/egress", body); code != 403 && code != 409 {
		t.Fatal("managed mode allowed local edit", code)
	}
}
