package removal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func testInstall(t *testing.T) installation {
	t.Helper()
	root := t.TempDir()
	p := installation{filepath.Join(root, "etc/bosun/config.yaml"), filepath.Join(root, "data"), filepath.Join(root, "bin/bosun"), filepath.Join(root, "systemd/bosun.service"), filepath.Join(root, "init.d/bosun")}
	for _, path := range []string{p.config, p.binary, p.systemd, p.openrc, filepath.Join(p.data, "captain.token")} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("test fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	raw := fmt.Sprintf("data_dir: %q\npanel:\n  driver: captain\n  captain:\n    url: https://panel.example.com\ncores:\n  singbox: {}\nweb:\n  listen: 127.0.0.1:0\n", p.data)
	if err := os.WriteFile(p.config, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}
func stateFixture() *agentproto.State {
	return &agentproto.State{Node: spec.Node{Inbounds: []spec.Inbound{{Tag: "test", Protocol: spec.VLESS, Port: 9443}}}, Users: []spec.User{{ID: 47, UUID: "11111111-1111-4111-8111-111111111111"}}}
}
func noopCleanup(context.Context, installation) error { return nil }
func noopReady(context.Context, string) error         { return nil }
func testPlan(mode, init string) Plan {
	return Plan{ID: "test-job", Init: init, Params: Params{Mode: mode, ExpiresAt: time.Now().Add(time.Minute).Unix()}, URL: "https://panel.example.com", Token: "test-token", State: stateFixture()}
}

func TestStandaloneServiceTransition(t *testing.T) {
	for _, init := range []string{"systemd", "openrc"} {
		t.Run(init, func(t *testing.T) {
			p := testInstall(t)
			old, pw, err := local.Open(filepath.Join(p.data, "local.json"), slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if err := old.Adopt("https://panel.example.com"); err != nil {
				t.Fatal(err)
			}
			var calls []string
			active := true
			run := func(_ context.Context, name string, args ...string) error {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if strings.Contains(calls[len(calls)-1], "stop") {
					active = false
				}
				if strings.Contains(calls[len(calls)-1], "start") {
					cfg, e := config.Load(p.config)
					if e != nil {
						return e
					}
					if cfg.Panel.Driver != "local" {
						return errors.New("started before conversion")
					}
					active = true
				}
				return nil
			}
			listen, login, err := execute(context.Background(), testPlan("standalone", init), run, p, noopCleanup, noopReady)
			if err != nil || login || listen != "127.0.0.1:0" || !active {
				t.Fatalf("transition: %q %v %v %v", listen, login, active, err)
			}
			s, _, err := local.Open(filepath.Join(p.data, "local.json"), slog.Default())
			if err != nil {
				t.Fatal(err)
			}
			if !s.Login("admin", pw) {
				t.Fatal("existing admin was replaced")
			}
			mode, managed, _ := s.Mode()
			if mode != local.ModeLocal || managed != nil || len(s.ListUsers()) != 1 || s.ListUsers()[0].TrafficID != 47 {
				t.Fatal("managed state not imported")
			}
			if _, err := os.Stat(filepath.Join(p.data, "captain.token")); !os.IsNotExist(err) {
				t.Fatal("old node token retained")
			}
			want := []string{"systemctl stop bosun", "systemctl start bosun", "systemctl is-active --quiet bosun"}
			if init == "openrc" {
				want = []string{"rc-service bosun stop", "rc-service bosun start", "rc-service bosun status"}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls: %v", calls)
			}
		})
	}
}

func TestStandaloneFailedReadinessRestoresManagedState(t *testing.T) {
	p := testInstall(t)
	originals := map[string][]byte{}
	for _, path := range []string{p.config, filepath.Join(p.data, "captain.token")} {
		originals[path], _ = os.ReadFile(path)
	}
	var calls []string
	run := func(_ context.Context, name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}
	_, _, err := execute(context.Background(), testPlan("standalone", "systemd"), run, p, noopCleanup, func(context.Context, string) error { return errors.New("web startup failed") })
	if err == nil {
		t.Fatal("failure lost")
	}
	for path, want := range originals {
		got, e := os.ReadFile(path)
		if e != nil || string(got) != string(want) {
			t.Fatalf("did not restore %s", path)
		}
	}
	if _, err := os.Stat(filepath.Join(p.data, "local.json")); !os.IsNotExist(err) {
		t.Fatal("created local state not rolled back")
	}
	want := []string{"systemctl stop bosun", "systemctl start bosun", "systemctl stop bosun", "systemctl start bosun"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("rollback ordering: %v", calls)
	}
}

func TestUninstallKeepDataAndStopFailure(t *testing.T) {
	for _, init := range []string{"systemd", "openrc"} {
		for _, keep := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/keep=%v", init, keep), func(t *testing.T) {
				p := testInstall(t)
				plan := testPlan("uninstall", init)
				plan.Params.KeepData = keep
				active := true
				cleaned := false
				run := func(_ context.Context, _ string, args ...string) error {
					if strings.Contains(strings.Join(args, " "), "stop") {
						active = false
					}
					return nil
				}
				cleanup := func(context.Context, installation) error {
					if active {
						t.Fatal("network cleanup before stop")
					}
					cleaned = true
					return nil
				}
				if _, _, err := execute(context.Background(), plan, run, p, cleanup, noopReady); err != nil {
					t.Fatal(err)
				}
				if !cleaned {
					t.Fatal("network cleanup skipped")
				}
				for _, path := range []string{p.binary, p.config} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("not removed: %s", path)
					}
				}
				_, err := os.Stat(p.data)
				if keep != (err == nil) {
					t.Fatalf("keep-data: %v", err)
				}
			})
		}
	}
	p := testInstall(t)
	_, _, err := execute(context.Background(), testPlan("uninstall", "systemd"), func(context.Context, string, ...string) error { return errors.New("stop failed") }, p, func(context.Context, installation) error { t.Fatal("cleanup after failed stop"); return nil }, noopReady)
	if err == nil {
		t.Fatal("stop failure lost")
	}
	if _, err := os.Stat(p.binary); err != nil {
		t.Fatal("binary removed while service active")
	}
}

func TestRemovalCallback(t *testing.T) {
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; t.Error("redirect followed") }))
	defer target.Close()
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/agent/removal" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("wrong callback")
		}
		var got Result
		if json.NewDecoder(r.Body).Decode(&got) != nil || got.ID != "test-job" {
			t.Error("wrong result")
		}
		if status == 302 {
			w.Header().Set("Location", target.URL)
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	p := testPlan("uninstall", "systemd")
	p.URL = srv.URL
	if err := notify(context.Background(), p, Result{ID: p.ID, Phase: "running"}); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{302, 401, 409, 500} {
		status = code
		if err := notify(context.Background(), p, Result{ID: p.ID, Phase: "complete"}); err == nil {
			t.Fatalf("accepted HTTP %d", code)
		}
	}
	if calls != 0 {
		t.Fatal("sent token on redirect")
	}
}

func TestRemovalPreconditions(t *testing.T) {
	for _, mutate := range []func(*Plan){func(p *Plan) { p.ID = "../bad" }, func(p *Plan) { p.Params.Mode = "shell" }, func(p *Plan) { p.Params.ExpiresAt = time.Now().Unix() }, func(p *Plan) { p.State = nil }, func(p *Plan) { p.Token = "" }} {
		p := testPlan("standalone", "systemd")
		mutate(&p)
		if validate(p, time.Now()) == nil {
			t.Fatal("invalid plan accepted")
		}
	}
}
