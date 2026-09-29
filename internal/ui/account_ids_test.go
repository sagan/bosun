package ui

import (
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/local"
)

func TestChangeUserIDAPI(t *testing.T) {
	st, pw, err := local.Open(filepath.Join(t.TempDir(), "state.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(local.User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: st, Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("PUT", "/api/users/1/id", map[string]int{"id": 42}); code != 401 {
		t.Fatalf("anonymous renumber: %d", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	if code, b := c.do("PUT", "/api/users/1/id", map[string]int{"id": 42}); code != 200 {
		t.Fatalf("renumber: %d %s", code, b)
	}
	if got, ok := st.User(42); !ok || got.UUID != u.UUID || got.SubToken != u.SubToken {
		t.Fatal("credentials changed")
	}
	if code, _ := c.do("PUT", "/api/users/42/id", map[string]int{"id": 0}); code != 400 {
		t.Fatal("invalid ID accepted")
	}
	if err := st.Adopt("https://example.com"); err != nil {
		t.Fatal(err)
	}
	if code, _ := c.do("PUT", "/api/users/42/id", map[string]int{"id": 7}); code != 409 {
		t.Fatal("managed mode allowed renumber")
	}
}
