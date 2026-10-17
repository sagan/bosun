package ui

import (
	"github.com/zeptop-dev/bosun/internal/local"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetiredExporterAPIs(t *testing.T) {
	st, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: st, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("GET", "/api/komari", nil); code != 401 {
		t.Fatal("unauthenticated", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatal(code, string(b))
	}
	for _, name := range []string{"komari", "dstatus"} {
		path := "/api/" + name
		if code, b := c.do("PUT", path, map[string]any{"enabled": true, "key": "retired-secret"}); code != 400 {
			t.Fatal(code, string(b))
		}
		if code, b := c.do("GET", path, nil); code != 200 || !strings.Contains(string(b), `"enabled":false`) || !strings.Contains(string(b), `"has_key":false`) {
			t.Fatal(code, string(b))
		}
		if code, b := c.do("PUT", path, map[string]any{"enabled": false}); code != 200 {
			t.Fatal(code, string(b))
		}
	}
	if err := st.Adopt("https://panel.example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("PUT", "/api/dstatus", map[string]any{"enabled": false}); code != 409 {
		t.Fatal("managed write", code)
	}
}
