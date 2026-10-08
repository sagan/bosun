package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

func extendedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestExtendedRenderIdentityAndBoth(t *testing.T) {
	u := spec.User{ID: 7, Name: "billing-7", UUID: "00000000-0000-4000-8000-000000000007", Password: "test-password"}
	ib := spec.Inbound{Tag: "test", Protocol: spec.Mieru, Core: "singbox-extended", Port: 24450, MieruTransport: "BOTH"}
	raw, err := render(&spec.Node{}, []spec.Inbound{ib}, []spec.User{u}, renderOptions{Distribution: "singbox-extended", StatsListen: "127.0.0.1:9105"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	ins := cfg["inbounds"].([]any)
	if len(ins) != 2 {
		t.Fatal(string(raw))
	}
	for _, item := range ins {
		in := item.(map[string]any)
		got := in["users"].([]any)[0].(map[string]any)["name"]
		if got != spec.ProxyUsername(u.UUID, ib.Tag) {
			t.Fatalf("wire identity %v", got)
		}
	}
	stats := cfg["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if len(stats["inbounds"].([]any)) != 2 {
		t.Fatal("UDP listener has no inbound counter")
	}
	if got := translateTraffic(map[string]spec.Traffic{"test": {Up: 2}, mieruUDPTag("test"): {Down: 3}}, map[string]string{mieruUDPTag("test"): "test"})["test"]; got.Up != 2 || got.Down != 3 {
		t.Fatal(got)
	}
}

// Opt in with an unmodified, pinned upstream build carrying with_v2ray_api.
// No host firewall changes; the allowed local echo target is test-only.
func TestExtendedRealSSHAndMieru(t *testing.T) {
	binary := os.Getenv("BOSUN_EXTENDED_TEST_BINARY")
	if binary == "" {
		t.Skip("BOSUN_EXTENDED_TEST_BINARY not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	u := spec.User{ID: 7, Name: "billing-7", UUID: "00000000-0000-4000-8000-000000000007", Password: "test-password"}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	stats := net.JoinHostPort("127.0.0.1", strconv.Itoa(extendedPort(t)))
	c, err := New(Options{Distribution: "singbox-extended", Binary: binary, WorkDir: t.TempDir(), StatsListen: stats}, log)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Stop(context.Background())
	sshIn := spec.Inbound{Tag: "ssh", Protocol: spec.SSH, Core: "singbox-extended", Listen: "127.0.0.1", Port: extendedPort(t)}
	spec.FillInboundSecrets(&sshIn)
	mieruIn := spec.Inbound{Tag: "mieru", Protocol: spec.Mieru, Core: "singbox-extended", Port: extendedPort(t), MieruTransport: "BOTH"}
	node := &spec.Node{AllowPrivateDest: true, Inbounds: []spec.Inbound{sshIn, mieruIn}}
	bundle, err := c.Render(node, node.Inbounds, []spec.User{u})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshIn.SSH.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	sshAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sshIn.Port))
	var client *ssh.Client
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{User: spec.ProxyUsername(u.UUID, "ssh"), Auth: []ssh.AuthMethod{ssh.Password(u.Password)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: time.Second})
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if session, err := client.NewSession(); err == nil {
		session.Close()
		t.Fatal("SSH shell channel accepted")
	}
	if bad, err := ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{User: spec.ProxyUsername(u.UUID, "ssh"), Auth: []ssh.AuthMethod{ssh.Password("wrong")}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: time.Second}); err == nil {
		bad.Close()
		t.Fatal("bad SSH password accepted")
	}
	checkEcho := func(conn net.Conn) {
		t.Helper()
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		payload := bytes.Repeat([]byte("data"), 8192)
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("echo mismatch")
		}
	}
	conn, err := client.Dial("tcp", echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	checkEcho(conn)
	for _, transport := range []string{"TCP", "UDP"} {
		port := mieruIn.Port
		if transport == "UDP" {
			port++
		}
		socksPort := extendedPort(t)
		config := m{"log": m{"level": "error"}, "inbounds": []any{m{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}}, "outbounds": []any{m{"type": "mieru", "tag": "proxy", "server": "127.0.0.1", "server_port": port, "transport": transport, "username": spec.ProxyUsername(u.UUID, "mieru"), "password": u.Password}}, "route": m{"final": "proxy"}}
		raw, _ := json.Marshal(config)
		path := filepath.Join(t.TempDir(), "client.json")
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
		var logs bytes.Buffer
		cmd.Stdout, cmd.Stderr = &logs, &logs
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		socksAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))
		dialer, _ := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{Timeout: 3 * time.Second})
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			conn, err = dialer.Dial("tcp", echo.Addr().String())
			if err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err == nil {
			checkEcho(conn)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if err != nil {
			t.Fatalf("Mieru %s: %v: %s", transport, err, logs.String())
		}
	}
	counters, err := c.Stats(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"ssh", "mieru"} {
		if traffic := counters[spec.InboundUser(u.Name, tag)]; traffic.Up < 32768 || traffic.Down < 32768 {
			t.Fatalf("%s lost per-user/per-inbound accounting: %+v", tag, counters)
		}
	}
	client.Close()
	node.AllowPrivateDest = false
	bundle, err = c.Render(node, node.Inbounds, []spec.User{u})
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Apply(ctx, bundle); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", sshAddr, &ssh.ClientConfig{User: spec.ProxyUsername(u.UUID, "ssh"), Auth: []ssh.AuthMethod{ssh.Password(u.Password)}, HostKeyCallback: ssh.FixedHostKey(hostKey), Timeout: time.Second})
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, err = client.Dial("tcp", echo.Addr().String())
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("blocked"))
		got := make([]byte, 7)
		if n, _ := conn.Read(got); n != 0 {
			t.Fatal("SSH bypassed private destination guard")
		}
	}
}
