package agent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/crypto/ssh"
)

// A real Extended process resets its memory on Apply/Stop. No report timer
// fires between the second/third transfer and those lifecycle operations.
func TestRealExtendedTrafficCheckpointAndAggregates(t *testing.T) {
	binary := os.Getenv("BOSUN_EXTENDED_TEST_BINARY")
	if binary == "" && os.Getenv("BOSUN_TEST_DOWNLOAD_CORES") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		release, ok := coreinstall.Default("singbox-extended")
		if !ok {
			t.Fatal("reviewed Extended package unavailable")
		}
		var err error
		binary, err = coreinstall.New(t.TempDir(), slog.Default()).Ensure(ctx, "singbox-extended", release.Version)
		if err != nil {
			t.Fatal(err)
		}
	}
	if binary == "" {
		t.Skip("set BOSUN_EXTENDED_TEST_BINARY")
	}
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := singbox.New(singbox.Options{Distribution: "singbox-extended", Binary: binary, WorkDir: t.TempDir(), StatsListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(port()))}, log)
	if err != nil {
		t.Fatal(err)
	}
	reg := core.NewRegistry()
	reg.Register(c)
	panel := &lostResponsePanel{seen: map[uint64]bool{}, lose: true}
	a := New(&config.Config{DataDir: t.TempDir()}, panel, reg, nil, log)
	defer a.stopAll()
	ib := spec.Inbound{Tag: "ssh", Protocol: spec.SSH, Core: "singbox-extended", Listen: "127.0.0.1", Port: port()}
	spec.FillInboundSecrets(&ib)
	a.node = &spec.Node{AllowPrivateDest: true, Inbounds: []spec.Inbound{ib}}
	user := spec.User{ID: 1, Name: "customer", UUID: "00000000-0000-4000-8000-000000000001", Password: "test-password"}
	a.users = []spec.User{user}
	a.rebuildUserIndex()
	if err = a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ib.SSH.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	const size = 32768
	transfer := func() {
		t.Helper()
		var client *ssh.Client
		var err error
		for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
			client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(ib.Port)), &ssh.ClientConfig{User: spec.ProxyUsername(user.UUID, ib.Tag), Auth: []ssh.AuthMethod{ssh.Password(user.Password)}, HostKeyCallback: ssh.FixedHostKey(key), Timeout: time.Second})
			if err == nil {
				break
			}
			time.Sleep(30 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		conn, err := client.Dial("tcp", echo.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("x"), size)
		if _, err = conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, size)
		if _, err = io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		conn.Close()
		client.Close()
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			counts, e := c.Stats(ctx, false)
			if e == nil && counts["customer|ssh"].Up == size && counts["customer|ssh"].Down == size {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("upstream transfer counters not ready")
	}
	transfer()
	a.report(ctx) // server accepted this report; response was lost
	if panel.total != size {
		t.Fatal("first transfer not charged", panel.total)
	}
	transfer()
	// Render/preflight must not replace a still-running core's accounting aliases.
	candidate := user
	candidate.Name = "replacement"
	if _, err = c.Render(a.node, a.node.Inbounds, []spec.User{candidate}); err != nil {
		t.Fatal(err)
	}
	before, err := c.Stats(ctx, false)
	if err != nil || before["customer|ssh"].Up != size {
		t.Fatal("render replaced active identity", before, err)
	}
	a.node.DNS = []string{"1.1.1.1"}
	if err = a.apply(ctx); err != nil {
		t.Fatal(err)
	}
	transfer()
	a.stopAll()
	a.trafficJournal = nil // lose all in-memory journal state, then replay from disk
	a.report(ctx)
	a.report(ctx)
	if panel.total != 3*size {
		t.Fatalf("reload/shutdown lost or doubled billing: %d", panel.total)
	}
	first, last := panel.reports[0], panel.reports[len(panel.reports)-1]
	for _, r := range []struct {
		in, out spec.Traffic
		want    int64
	}{{first.Inbounds["ssh"], first.Outbounds["direct"], size}, {last.Inbounds["ssh"], last.Outbounds["direct"], 2 * size}} {
		if r.in.Up != r.want || r.in.Down != r.want || r.out.Up != r.want || r.out.Down != r.want {
			t.Fatalf("selective resets lost native aggregate: %+v", r)
		}
	}
}
