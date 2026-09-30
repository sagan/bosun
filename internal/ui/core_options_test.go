package ui

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/agent"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Only capability probing is exercised; no subprocess methods may be called.
type idleCore struct {
	core.Core
	name string
}

func (c idleCore) Name() string                    { return c.name }
func (c idleCore) Capabilities() core.Capabilities { return spec.CapabilitiesForCore(c.name) }
func (c idleCore) Running() bool                   { return false }

func TestCoreOptionsLocalAPI(t *testing.T) {
	store, pw, err := local.Open(filepath.Join(t.TempDir(), "local.json"), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	reg := core.NewRegistry()
	reg.Register(idleCore{name: "xray"})
	s := New(Deps{Store: store, Log: slog.Default()})
	s.SetAgent(agent.New(&config.Config{}, store, reg, nil, slog.Default()))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	path := "/api/inbounds/core-options?protocol=vless"
	if code, _ := c.do("GET", path, nil); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, b := c.do("POST", "/api/login", map[string]string{"Username": "admin", "Password": pw}); code != 200 {
		t.Fatalf("login: %d %s", code, b)
	}
	code, b := c.do("GET", path, nil)
	var p spec.CoreOptions
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	if code != 200 || !p.InventoryKnown || p.AutoCore != "xray" || *p.Options[0].Available || !*p.Options[1].Available {
		t.Fatalf("idle core availability: %d %s", code, b)
	}
	ib := map[string]any{"tag": "in", "protocol": "vless", "port": 24443, "core": "singbox", "enabled": true}
	if code, b := c.do("POST", "/api/inbounds", ib); code != 400 {
		t.Fatalf("unavailable pin: %d %s", code, b)
	}
	ib["core"] = "xray"
	if code, b := c.do("POST", "/api/inbounds", ib); code != 200 {
		t.Fatalf("idle enabled core: %d %s", code, b)
	}
	ib["transport"] = map[string]any{"type": "http"}
	if code, b := c.do("PUT", "/api/inbounds/in", ib); code != 400 {
		t.Fatalf("incompatible edit: %d %s", code, b)
	}
	if stored := store.Inbounds(); len(stored) != 1 || stored[0].Core != "xray" || stored[0].Transport != nil {
		t.Fatalf("rejected edit changed inbound: %+v", stored)
	}
}
