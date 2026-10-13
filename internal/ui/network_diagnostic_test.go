package ui

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestStandaloneNetworkDiagnosticAccess(t *testing.T) {
	st, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Store: st, Version: "test", Log: slog.Default()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	p := spec.DiagnosticRequest{Type: "http", Target: srv.URL + "/api/status"}
	if code, _ := c.do("POST", "/api/diagnostics/network", p); code != 401 {
		t.Fatal("unauthenticated", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatal(code, string(b))
	}
	code, b := c.do("POST", "/api/diagnostics/network", p)
	var result spec.DiagnosticResult
	if json.Unmarshal(b, &result) != nil || code != 200 || result.Outcome != "http_status" || result.Measurement.HTTPStatus != 401 {
		t.Fatal(code, string(b))
	}
	if code, _ = c.do("POST", "/api/diagnostics/network", spec.DiagnosticRequest{Type: "mtr", Target: "--help"}); code != 400 {
		t.Fatal("invalid", code)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/api/diagnostics/network", nil)
	req.Header.Set("Origin", "https://other.example.com")
	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal("cross origin", resp.StatusCode)
	}
	if err = st.Adopt("https://panel.example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _ = c.do("POST", "/api/diagnostics/network", p); code != 409 {
		t.Fatal("managed write", code)
	}
}

// Every cookie-authenticated write refuses a request a foreign origin made
// the browser send, and so does the login that mints the cookie. A bearer
// token is not ambient, so it is unaffected.
func TestCookieWritesRefuseCrossOrigin(t *testing.T) {
	st, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	s := New(Deps{Store: st, Version: "test", Log: slog.Default()})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	send := func(path string, body string, origin string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	login := `{"Username":"admin","Password":"` + pw + `"}`
	if code := send("/api/login", login, "https://other.example.com"); code != 403 {
		t.Fatal("cross-origin login", code)
	}
	if code := send("/api/login", login, srv.URL); code != 200 {
		t.Fatal("same-origin login", code)
	}
	if code := send("/api/users", `{"Name":"x"}`, "https://other.example.com"); code != 403 {
		t.Fatal("cross-origin write with a session cookie", code)
	}
	if code := send("/api/users", `{"Name":"x"}`, srv.URL); code == 403 || code == 401 {
		t.Fatal("same-origin write refused", code)
	}
}
