package agent

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/firewall"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestForwardChangesImmediatelyReconcileFirewall(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg := &config.Config{DataDir: t.TempDir(), Forwards: []config.ForwardRule{{Tag: "test-forward", Protocol: "tcp", Listen: "127.0.0.1", Port: port, Target: "127.0.0.1:9"}}}
	a := New(cfg, nopDriver{}, core.NewRegistry(), nil, slog.Default())
	defer a.fwd.Stop()
	a.node = &spec.Node{}
	a.kernelNode = a.node
	a.kernelByTag = map[string]string{}
	rules := map[string]string{}
	a.Firewall = &firewall.Manager{StateFile: filepath.Join(cfg.DataDir, "firewall.json"), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "status" {
			return []byte("Status: active\n"), nil
		}
		if strings.Join(args, " ") == "show added" {
			var s []string
			for _, r := range rules {
				s = append(s, r)
			}
			return []byte(strings.Join(s, "\n")), nil
		}
		if args[0] == "allow" {
			rules[args[1]] = "ufw allow " + args[1] + " comment '" + args[3] + "'"
		} else if args[0] == "delete" {
			delete(rules, args[2])
		}
		return nil, nil
	}}
	if err = a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := rules[strconv.Itoa(port)+"/tcp"]; !ok {
		t.Fatal("forward started without immediate firewall synchronization")
	}
	st := a.Firewall.Status()
	if len(st.Rules) != 1 || len(st.Rules[0].Sources) != 1 || st.Rules[0].Sources[0] != "forward:test-forward" {
		t.Fatalf("%+v", st)
	}
	cfg.Forwards = nil
	if err = a.applyForwards(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatal("deleted forward allowance left behind")
	}
}
