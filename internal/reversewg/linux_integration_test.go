package reversewg

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Reexec under unshare before touching networking. No host interface, sysctl,
// route, nft table or namespace name is modified by this fixture.
func TestLinuxTransport(t *testing.T) {
	if os.Getenv("BOSUN_REVERSEWG_TEST") != "1" {
		t.Skip("set BOSUN_REVERSEWG_TEST=1 on Linux with wg/ip/nft/python3")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("Linux required")
	}
	if os.Getenv("BOSUN_REVERSEWG_CHILD") != "1" {
		// Download before entering the isolated namespace, which has no Internet.
		if os.Getenv("BOSUN_TEST_DOWNLOAD_CORES") == "1" && os.Getenv("BOSUN_XRAY_TEST_BINARY") == "" {
			release, ok := coreinstall.Tested("xray")
			if !ok {
				t.Fatal("no tested Xray release")
			}
			installer := coreinstall.New(t.TempDir(), slog.Default())
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			binary, err := installer.Ensure(ctx, "xray", release.Version)
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("BOSUN_XRAY_TEST_BINARY", binary)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "-n", os.Args[0], "-test.run=^TestLinuxTransport$", "-test.v")
		cmd.Env = append(os.Environ(), "BOSUN_REVERSEWG_CHILD=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("isolated fixture: %v\n%s", err, out)
		} else {
			t.Log(string(out))
		}
		return
	}
	run := func(pid int, stdin string, name string, args ...string) string {
		t.Helper()
		if pid > 0 {
			args = append([]string{"-t", strconv.Itoa(pid), "-n", name}, args...)
			name = "nsenter"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			// wg diagnostics can quote malformed private key material.
			if strings.Contains(stdin, "PrivateKey") {
				t.Fatalf("WireGuard configuration failed: %v", err)
			}
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	child := func() int {
		cmd := exec.Command("unshare", "-n", "sleep", "90")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		pid := cmd.Process.Pid
		// Wait for unshare, not merely fork; the namespace must differ.
		self, _ := os.Readlink("/proc/self/ns/net")
		for i := 0; i < 100; i++ {
			ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
			if ns != "" && ns != self {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("child namespace not ready")
		return 0
	}
	bpid, target, bpid2, target2 := child(), child(), child(), child()
	run(0, "", "ip", "link", "set", "lo", "up")
	for i, pair := range [][2]int{{bpid, target}, {bpid2, target2}} {
		bp, tp := pair[0], pair[1]
		for _, pid := range []int{bp, tp} {
			run(pid, "", "ip", "link", "set", "lo", "up")
		}
		uplink := fmt.Sprintf("uplink%d", i)
		run(0, "", "ip", "link", "add", uplink, "type", "veth", "peer", "name", "outside")
		run(0, "", "ip", "link", "set", "outside", "netns", strconv.Itoa(bp))
		for _, x := range []struct {
			pid       int
			dev, addr string
		}{{0, uplink, fmt.Sprintf("192.0.2.%d/30", i*4+1)}, {bp, "outside", fmt.Sprintf("192.0.2.%d/30", i*4+2)}} {
			run(x.pid, "", "ip", "addr", "add", x.addr, "dev", x.dev)
			run(x.pid, "", "ip", "link", "set", x.dev, "up")
		}
		run(bp, "", "ip", "link", "add", "lan", "type", "veth", "peer", "name", "target")
		run(bp, "", "ip", "link", "set", "target", "netns", strconv.Itoa(tp))
		for _, x := range []struct {
			pid         int
			dev, a4, a6 string
		}{{bp, "lan", "10.20.0.1/24", "fd20::1/64"}, {tp, "target", "10.20.0.2/24", "fd20::2/64"}} {
			run(x.pid, "", "ip", "addr", "add", x.a4, "dev", x.dev)
			run(x.pid, "", "ip", "-6", "addr", "add", x.a6, "dev", x.dev, "nodad")
			run(x.pid, "", "ip", "link", "set", x.dev, "up")
		}
	}

	// Target has no default route: success proves B's SNAT return path.
	run(0, "", "ip", "route", "add", "default", "via", "192.0.2.2")
	a, b := pair(t)
	b.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.20.0.0/24", PortStart: 18080}, {CIDR: "fd20::/64", PortStart: 18080}}}
	a.PrivateAccess = b.PrivateAccess
	managers := map[int]*Manager{}
	install := func(pid int, configs ...Config) {
		backend := &Linux{}
		if pid > 0 {
			backend.Run = func(ctx context.Context, c Command) ([]byte, error) {
				ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				args := append([]string{"-t", strconv.Itoa(pid), "-n", c.Name}, c.Args...)
				cmd := exec.CommandContext(ctx, "nsenter", args...)
				cmd.Stdin = strings.NewReader(c.Stdin)
				out, err := cmd.Output()
				if err != nil {
					return nil, fmt.Errorf("isolated %s failed: %w", c.Name, err)
				}
				return out, nil
			}
		}
		m := &Manager{Dir: t.TempDir(), Backend: backend}
		managers[pid] = m
		if _, err := m.Reconcile(context.Background(), configs, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("initial reconcile: %v", err)
		}
		if !backend.Healthy(context.Background(), configs) {
			in, e := backend.inventory(context.Background())
			raw, _ := backend.command(context.Background(), "ip", "-j", "-d", "link", "show")
			t.Log(string(raw))
			t.Fatalf("unhealthy fixture inventory: %+v err=%v", in, e)
		}
		if changed, err := m.Reconcile(context.Background(), configs, func(context.Context) error { t.Fatal("healthy reconcile stopped proxy"); return nil }); err != nil || changed {
			t.Fatalf("healthy reconcile failed: %v", err)
		}
	}

	a2, b2 := pair(t)
	a2.Slot, b2.Slot = 2, 2
	a2.ListenPort = 51821
	b2.Endpoint = "192.0.2.5:51821"
	b2.PrivateAccess = b.PrivateAccess
	a2.PrivateAccess = b.PrivateAccess
	install(0, a, a2)
	install(bpid, b)
	install(bpid2, b2)

	startServer := func(pid int, script string) {
		server := exec.Command("nsenter", "-t", strconv.Itoa(pid), "-n", "python3", "-u", "-c", script)
		var stderr bytes.Buffer
		server.Stderr = &stderr
		ready, err := server.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
		if line, err := bufio.NewReader(ready).ReadString('\n'); err != nil || line != "ready\n" {
			t.Fatalf("server failed: %v: %s", err, stderr.String())
		}
	}
	run(bpid, "", "ip", "addr", "add", "10.10.0.2/32", "dev", "outside")
	startServer(bpid, strings.ReplaceAll(echoServer, "[(socket.AF_INET,'10.20.0.2'),(socket.AF_INET6,'fd20::2')]", "[(socket.AF_INET,'10.10.0.2')]"))
	startServer(target, echoServer)
	// Distinct replies prove that equal destination subnets stay isolated.
	startServer(target2, strings.ReplaceAll(echoServer, "c.sendall(data)", "c.sendall(data.upper())"))
	startServer(bpid, strings.NewReplacer("10.20.0.2", "10.20.0.1", "fd20::2", "fd20::1").Replace(echoServer))

	// Wait for B's initial handshake before probing the data path.
	for i := 0; i < 50; i++ {
		if !strings.HasSuffix(strings.TrimSpace(run(bpid, "", "wg", "show", b.Interface(), "latest-handshakes")), "\t0") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, x := range []struct {
		pid int
		c   Config
	}{{0, a}, {bpid, b}, {0, a2}, {bpid2, b2}} {
		st, err := ParseStatus(x.c, run(x.pid, "", "wg", "show", x.c.Interface(), "latest-handshakes"), run(x.pid, "", "wg", "show", x.c.Interface(), "transfer"), time.Now())
		if err != nil || !st.Connected {
			t.Fatalf("desired peer handshake not confirmed: %v", err)
		}
	}
	// Force an MTU bottleneck after the tunnel. The connected UDP socket
	// must receive the related error; a timeout would hide a PMTU black hole.
	run(bpid, "", "ip", "link", "set", "lan", "mtu", "1280")
	for _, v6 := range []bool{false, true} {
		dest := "10.20.0.2"
		if v6 {
			dest = "fd20::2"
		}
		run(0, "", "python3", "-c", pmtuClient, a.Address(false, v6), dest)
	}
	run(bpid, "", "ip", "link", "set", "lan", "mtu", "1500")
	probe := func(source, dest string, success bool) {
		expect := "0"
		if success {
			expect = "1"
		}
		run(0, "", "python3", "-c", probeClient, source, dest, expect)
	}
	probe(a.Address(false, false), "10.20.0.2", true)
	probe(a.Address(false, true), "fd20::2", true)
	probe2 := strings.ReplaceAll(probeClient, "==b'reversewg'", "==b'REVERSEWG'")
	// UDP is unchanged on the second echo service; check TCP identity here.
	probe2 = strings.ReplaceAll(probe2, "[False,True]", "[False]")
	run(0, "", "python3", "-c", probe2, a2.Address(false, false), "10.20.0.2", "1")
	run(0, "", "python3", "-c", probe2, a2.Address(false, true), "fd20::2", "1")

	// Even a broad LAN grant must not expose B's own management services.
	probe(a.Address(false, false), "10.20.0.1", false)
	shared := &shaper.Shared{Dir: t.TempDir(), Legacy: &shaper.Shaper{Interface: "uplink0"}}
	sharedDevices := []string{"uplink0", "uplink1", a.Interface(), a2.Interface()}
	quiesces := 0
	applyLimits := func(limits []shaper.Limit) error {
		return shared.Reconcile(context.Background(), sharedDevices, limits, func(context.Context) error { quiesces++; return nil })
	}
	if err := applyLimits([]shaper.Limit{{UserID: 1, Mbps: 2}}); err != nil {
		for _, dev := range sharedDevices {
			for _, direction := range []string{"ingress", "egress"} {
				t.Logf("tc filters %s %s: %s", dev, direction, run(0, "", "tc", "-j", "filter", "show", "dev", dev, direction))
			}
		}
		t.Fatalf("shared shaper: %v", err)
	}
	if err := applyLimits([]shaper.Limit{{UserID: 1, Mbps: 2}}); err != nil {
		t.Fatalf("shared shaper repeat: %v", err)
	}

	if quiesces != 1 {
		t.Fatal("healthy shared shaping interrupted proxies")
	}
	// Deleting a shaping IFB must not leave stale redirect targets or a
	// silently unlimited user. Restore before opening proxy sockets.
	run(0, "", "ip", "link", "delete", "ifb-bosun")
	if err := applyLimits([]shaper.Limit{{UserID: 1, Mbps: 2}}); err != nil {
		t.Log(run(0, "", "tc", "-j", "filter", "show", "dev", a.Interface(), "ingress"))
		t.Fatalf("shared shaping lost IFB recovery: %v", err)
	}
	run(0, "", "python3", "-c", bulkClient, a.Address(false, false)+","+a2.Address(false, false), "10.20.0.2")
	for _, dev := range []string{"ifb-bosun-up", "ifb-bosun"} {
		stats := run(0, "", "tc", "-s", "class", "show", "dev", dev)
		found := false
		for _, block := range strings.Split(stats, "class ") {
			if strings.HasPrefix(block, "htb 1:2 ") {
				fields := strings.Fields(block)
				for i, f := range fields {
					if f == "Sent" && i+1 < len(fields) {
						n, err := strconv.ParseUint(fields[i+1], 10, 64)
						if err != nil || n < 1000000 {
							t.Fatalf("user bytes missing on %s: %s", dev, block)
						}
						found = true
						break
					}
				}
			}
		}
		if !found {
			t.Fatalf("user class missing on %s", dev)
		}
	}
	testProxyAccounting(t, a, a2, b.PrivateAccess, applyLimits)
	run(bpid2, "", "ip", "link", "set", b2.Interface(), "down")
	run(0, "", "python3", "-c", probe2, a2.Address(false, false), "10.20.0.2", "0")
	probe(a.Address(false, false), "10.20.0.2", true)
	run(bpid2, "", "ip", "link", "set", b2.Interface(), "up")
	stream := exec.Command("python3", "-u", "-c", streamClient, a.Address(false, false), "10.20.0.2")
	streamOut, err := stream.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	streamIn, err := stream.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var streamErr bytes.Buffer
	stream.Stderr = &streamErr
	if err := stream.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Process.Kill() })
	if line, err := bufio.NewReader(streamOut).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("stream failed: %v", err)
	}
	// Revoke both directions without deleting conntrack state.
	b.PrivateAccess = nil
	s, err := Firewall([]Config{b})
	if err != nil {
		t.Fatal(err)
	}
	run(bpid, "delete table inet "+firewallTable+"\n"+s, "nft", "-f", "-")
	_, _ = streamIn.Write([]byte("revoked\n"))
	_ = streamIn.Close()
	if err := stream.Wait(); err != nil {
		t.Fatalf("existing download survived revocation: %v %s", err, streamErr.String())
	}
	probe(a.Address(false, false), "10.20.0.2", false)
	probe(a.Address(false, true), "fd20::2", false)
	// Remove both the interface and source rule. The output guard must
	// still reject sockets bound to A's old tunnel address.
	run(0, "", "ip", "link", "delete", a.Interface())
	run(0, "", "ip", "-4", "rule", "delete", "priority", strconv.Itoa(12000+a.Slot))
	run(0, "", "ip", "addr", "add", a.Address(false, false)+"/32", "dev", "lo")
	probe(a.Address(false, false), "10.20.0.2", false)
	var counters map[string]any
	if err := json.Unmarshal([]byte(run(0, "", "nft", "-j", "list", "chain", "inet", firewallTable, "output")), &counters); err != nil {
		t.Fatal(err)
	}
	var packets float64
	var walk func(any)
	walk = func(x any) {
		switch v := x.(type) {
		case map[string]any:
			if c, ok := v["counter"].(map[string]any); ok {
				if n, ok := c["packets"].(float64); ok {
					packets += n
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(counters)
	if packets == 0 {
		t.Fatal("missing-interface test did not exercise fallback guard")
	}
	run(0, "", "ip", "link", "delete", "ifb-bosun-up")
	sharedRestart := &shaper.Shared{Dir: shared.Dir, Legacy: &shaper.Shaper{Interface: "uplink0"}}
	if err := sharedRestart.Apply(context.Background(), nil, nil); err != nil {
		t.Fatalf("shared shaper restart cleanup: %v", err)
	}
	// Restart with an empty desired state must discover persisted ownership
	// and clean partial state, including the manually removed A interface.
	for _, pid := range []int{0, bpid, bpid2} {
		prior := managers[pid]
		restarted := &Manager{Dir: prior.Dir, Backend: prior.Backend}
		stopped := false
		if changed, err := restarted.Reconcile(context.Background(), nil, func(context.Context) error { stopped = true; return nil }); err != nil || !changed || !stopped {
			t.Fatalf("restart cleanup failed: %v", err)
		}
		data, err := readJournal(prior.Dir)
		if err != nil || len(data) != 0 {
			t.Fatal("cleanup did not clear ownership")
		}
	}
	// Crash immediately after link-add, before alias/WG configuration.
	partial := a
	partial.Slot = 3
	if err := saveJournal(managers[0].Dir, []Ownership{{Slot: 3}}); err != nil {
		t.Fatal(err)
	}
	partialPlan, err := CreatePlan(partial)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := managers[0].Backend.(*Linux).run(context.Background(), partialPlan[0]); err != nil {
		t.Fatal(err)
	}
	restart := &Manager{Dir: managers[0].Dir, Backend: managers[0].Backend}
	if _, err := restart.Reconcile(context.Background(), nil, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("partial-create recovery: %v", err)
	}
	// Do not claim or remove an unrelated interface using our preferred name.
	foreign := a
	foreign.Slot = 4
	run(0, "", "ip", "link", "add", foreign.Interface(), "type", "dummy")
	if _, err := restart.Reconcile(context.Background(), []Config{foreign}, func(context.Context) error { t.Fatal("foreign collision quiesced without owned resources"); return nil }); err == nil {
		t.Fatal("foreign interface accepted")
	}
	run(0, "", "ip", "link", "show", "dev", foreign.Interface())
	run(0, "", "ip", "link", "delete", "dev", foreign.Interface())
	t.Log("dual-stack TCP/UDP, SNAT without target route, overlapping exits, aggregate marked socket shaping, local isolation, existing-stream revocation and missing-interface rejection passed")
}

const echoServer = `
import socket,threading,time
def serve(s,udp):
 while True:
  if udp:
   data,peer=s.recvfrom(4096);s.sendto(data,peer)
  else:
   c,_=s.accept()
   def echo(c):
    try:
     while True:
      data=c.recv(4096)
      if not data:break
      if data==b'stream':
       while True:c.sendall(b'x'*64);time.sleep(.02)
      c.sendall(data)
    finally:c.close()
   threading.Thread(target=echo,args=(c,),daemon=True).start()
for fam,addr in [(socket.AF_INET,'10.20.0.2'),(socket.AF_INET6,'fd20::2')]:
 for udp in [False,True]:
  s=socket.socket(fam,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.bind((addr,18080))
  if not udp:s.listen()
  threading.Thread(target=serve,args=(s,udp),daemon=True).start()
print('ready',flush=True);time.sleep(80)
`

const probeClient = `
import socket,sys
source,dest,expected=sys.argv[1:];expected=expected=='1'
for udp in [False,True]:
 s=socket.socket(socket.AF_INET6 if ':' in dest else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
 s.settimeout(.7);s.bind((source,0));ok=False
 try:
  s.connect((dest,18080));s.send(b'reversewg');ok=s.recv(16)==b'reversewg'
 except OSError:pass
 finally:s.close()
 assert ok==expected,('unexpected reachability',dest,udp,ok)
`

const streamClient = `
import socket,sys,time
s=socket.socket();s.settimeout(2);s.bind((sys.argv[1],0));s.connect((sys.argv[2],18080));s.sendall(b'stream');assert s.recv(64)
print('ready',flush=True);sys.stdin.readline()
# Drain bytes already delivered before the atomic policy change.
s.settimeout(.1);deadline=time.monotonic()+1
while time.monotonic()<deadline:
 try:s.recv(4096)
 except socket.timeout:pass
s.settimeout(.4)
try:
 data=s.recv(4096)
 assert not data,'private download still receiving after revocation'
except socket.timeout:pass
s.close()
`

const bulkClient = `
import socket,sys,time,threading
payload=b'x'*(512*1024)
errors=[]
def transfer(source):
 try:
  s=socket.socket();s.settimeout(8);s.setsockopt(socket.SOL_SOCKET,36,65537);s.bind((source,0));s.connect((sys.argv[2],18080))
  sender=threading.Thread(target=s.sendall,args=(payload,));sender.start()
  received=0
  while received<len(payload):
   data=s.recv(65536)
   assert data
   received+=len(data)
  sender.join();s.close()
 except Exception as e:errors.append(repr(e))
threads=[threading.Thread(target=transfer,args=(source,)) for source in sys.argv[1].split(',')]
start=time.monotonic()
for t in threads:t.start()
for t in threads:t.join()
assert not errors,errors
elapsed=time.monotonic()-start
assert elapsed>=3.5,('aggregate 2 Mbps cap bypassed',elapsed)
`

const pmtuClient = `
import socket,sys,errno
source,dest=sys.argv[1:];v6=':' in dest
s=socket.socket(socket.AF_INET6 if v6 else socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(2);s.bind((source,0));s.connect((dest,18080))
if not v6:s.setsockopt(socket.IPPROTO_IP,10,2) # IP_MTU_DISCOVER = IP_PMTUDISC_DO
s.send(b'x'*1300)
try:
 s.recv(4096)
 raise AssertionError('oversized packet unexpectedly delivered')
except OSError as e:
 assert e.errno==errno.EMSGSIZE,('PMTU error missing',repr(e))
# Linux cached the learned MTU; this also distinguishes a real ICMP error.
mtu=s.getsockopt(socket.IPPROTO_IPV6 if v6 else socket.IPPROTO_IP,24 if v6 else 14)
assert mtu==1280,('unexpected learned MTU',mtu)
s.close()
`
