package reversewg

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Called only inside TestLinuxTransport's disposable network namespace.
func testProxyAccounting(t *testing.T, a, a2 Config, grant *spec.PrivateAccess, applyLimits func([]shaper.Limit) error) {
	t.Helper()
	binary := os.Getenv("BOSUN_XRAY_TEST_BINARY")
	if binary == "" {
		t.Log("real proxy accounting not requested; set BOSUN_XRAY_TEST_BINARY")
		return
	}
	dir, err := os.MkdirTemp("", "bosun-wg-core-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	// The installed production binary may live below a root-only directory.
	// Copy its public executable, never its configuration, into this fixture.
	source, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	target, err := os.OpenFile(filepath.Join(dir, "xray"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(target, source)
	source.Close()
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal("copy test binary failed")
	}
	a.PrivateAccess, a2.PrivateAccess = grant, grant
	user := spec.User{ID: 1, Name: "subscriber", UUID: "11111111-1111-4111-8111-111111111111", SpeedLimitMbps: 2}
	n := spec.Node{WireGuardLinks: []spec.WireGuardLink{a, a2}, Inbounds: []spec.Inbound{
		{Tag: "wg-one", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18443, WireGuardSlot: a.Slot, PrivateAccess: grant},
		{Tag: "wg-two", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18444, WireGuardSlot: a2.Slot, PrivateAccess: grant},
		{Tag: "ordinary", Core: "xray", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 18445, PrivateAccess: &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2/32", Protocol: "tcp", PortStart: 18080}}}},
	}}
	c, err := xray.New(xray.Options{Binary: filepath.Join(dir, "xray"), WorkDir: dir, APIListen: "127.0.0.1:19102", LogLevel: "warning"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := c.Render(&n, n.Inbounds, []spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range bundle.Files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	grants, err := n.PrivateGrants([]spec.User{user})
	if err != nil {
		t.Fatal(err)
	}
	limit := shaper.Limit{UserID: user.ID, Mbps: 2}
	for _, g := range grants {
		if g.UserID == user.ID {
			limit.Marks = append(limit.Marks, g.Mark)
		}
	}
	if err := applyLimits([]shaper.Limit{limit}); err != nil {
		t.Fatal(err)
	}
	guard := &egressguard.Guard{}
	if err := guard.Apply(context.Background(), 65534, egressguard.Options{PrivateGrants: grants, LoopbackPorts: []int{53}, ProtectedPorts: []int{19102}}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := guard.Apply(context.Background(), -1, egressguard.Options{Disabled: true}); err != nil {
			t.Error(err)
		}
	}()
	cmd := exec.Command("setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=+net_admin,+net_bind_service", "--ambient-caps=+net_admin,+net_bind_service", filepath.Join(dir, "xray"), "run", "-c", filepath.Join(dir, bundle.Main))
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ready := false
	for i := 0; i < 100; i++ {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:18443", 50*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatal("non-root Xray did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, "python3", "-c", proxyTraffic)
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("real proxy data path: %v\n%s", err, out)
	}
	// TCP stream accounting can settle just after the client closes.
	var counters map[string]spec.Traffic
	for i := 0; i < 30; i++ {
		counters, err = c.Stats(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		complete := true
		for _, ib := range n.Inbounds {
			v := counters[spec.InboundUser(user.Name, ib.Tag)]
			complete = complete && v.Up >= 512*1024 && v.Down >= 512*1024
		}
		if complete {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, ib := range n.Inbounds {
		v := counters[spec.InboundUser(user.Name, ib.Tag)]
		if v.Up != 512*1024 || v.Down != 512*1024 {
			t.Fatalf("payload billing mismatch for %s: %+v", ib.Tag, v)
		}
	}
	for name := range counters {
		if !strings.HasPrefix(name, user.Name+"|") {
			t.Fatalf("transport identity entered user accounting: %s", name)
		}
	}
	t.Log("non-root pinned Xray: two WG exits plus ordinary egress, private socket marks, shared 2 Mbps limit and exact per-inbound payload billing passed")
}

const proxyTraffic = `
import socket,struct,uuid,threading,time
errors=[]
payload=b'x'*(512*1024)
def exact(s,n):
 data=b''
 while len(data)<n:
  part=s.recv(n-len(data))
  assert part
  data+=part
 return data
def transfer(port):
 try:
  s=socket.create_connection(('127.0.0.1',port),2);s.settimeout(10)
  target=b'\x01'+socket.inet_aton('10.10.0.2' if port==18445 else '10.20.0.2')
  s.sendall(b'\x00'+uuid.UUID('11111111-1111-4111-8111-111111111111').bytes+b'\x00\x01'+struct.pack('!H',18080)+target)
  sender=threading.Thread(target=s.sendall,args=(payload,));sender.start()
  header=exact(s,2);exact(s,header[1])
  result=exact(s,len(payload));sender.join();s.close()
  assert result==(payload.upper() if port==18444 else payload)
 except Exception as e:errors.append(repr(e))
start=time.monotonic()
threads=[threading.Thread(target=transfer,args=(p,)) for p in [18443,18444,18445]]
for t in threads:t.start()
for t in threads:t.join()
assert not errors,errors
assert time.monotonic()-start>=5.5,'proxy bypassed aggregate user cap'
`
