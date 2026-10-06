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
)

func TestNATIngressAPICompatibility(t *testing.T) {
	st, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Deps{Store: st, Version: "test", Log: slog.Default()}).Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	if code, _ := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatal("login", code)
	}
	call := func(method, path string, body any, want int) []byte {
		t.Helper()
		code, b := c.do(method, path, body)
		if code != want {
			t.Fatalf("%s %s: %d %s", method, path, code, b)
		}
		return b
	}
	// Snake_case round-trip and PascalCase form writes both retain the policy.
	body := map[string]any{"name": "NAT", "kind": "nat", "entry_host": "203.0.113.30", "require_ingress": true, "port_mappings": []map[string]int{{"local_from": 20000, "local_to": 20009, "public_from": 30000}, {"local_from": 40000, "local_to": 40000, "public_from": 443}}, "reserved_ports": []int{20000}}
	var g local.Ingress
	if err := json.Unmarshal(call("POST", "/api/ingresses", body, 200), &g); err != nil {
		t.Fatal(err)
	}
	call("POST", "/api/inbounds", map[string]any{"tag": "m", "protocol": "mieru", "port": 40000, "enabled": true, "ingress_id": g.ID}, 200)
	call("POST", "/api/users", map[string]any{"name": "test", "enabled": true}, 200)
	if b := call("GET", "/api/users/1/links", nil, 200); !strings.Contains(string(b), "203.0.113.30?port=443") {
		t.Fatalf("unmapped link: %s", b)
	}
	call("POST", "/api/forwards", map[string]any{"tag": "f", "port": 20001, "protocol": "tcp", "target": "198.51.100.20:443", "ingress_id": g.ID}, 200)
	call("PUT", "/api/forwards/f", map[string]any{"tag": "f", "port": 20000, "target": "198.51.100.20:443", "ingress_id": g.ID}, 400)
	call("PUT", "/api/forwards/f", map[string]any{"tag": "f", "port": 20001, "target": "198.51.100.20:443"}, 400)
	old := map[string]any{"Name": "Renamed", "EntryHost": "203.0.113.30", "ReservedPorts": []int{20000}, "PortMappings": nil, "RequireIngress": nil}
	call("PUT", "/api/ingresses/"+g.ID, old, 200)
	saved, ok := st.Ingress(g.ID)
	if !ok || !saved.RequireIngress || saved.Kind != "nat" || saved.EntryPort(40000) != 443 {
		t.Fatal("old client cleared policy", saved)
	}
	old["RequireIngress"] = false
	call("PUT", "/api/ingresses/"+g.ID, old, 200)
	saved, _ = st.Ingress(g.ID)
	if saved.RequireIngress {
		t.Fatal("explicit false ignored")
	}
	old["ReservedPorts"] = []int{70000}
	call("PUT", "/api/ingresses/"+g.ID, old, 400)
	call("DELETE", "/api/ingresses/"+g.ID, nil, 400)
}
