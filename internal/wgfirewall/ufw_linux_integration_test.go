//go:build linux

package wgfirewall

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// The outer process performs no firewall/mount/network writes. It always
// reexecs in fresh mount and network namespaces, then the child independently
// refuses the host namespaces. UFW configuration and /run are private mounts;
// no operator hooks or sysctl configuration are copied into the fixture.
func TestUFWForwardingLinux(t *testing.T) {
	if os.Getenv("BOSUN_WG_FIREWALL_TEST") != "1" {
		t.Skip("set BOSUN_WG_FIREWALL_TEST=1 on an isolated Linux test machine")
	}
	if os.Geteuid() != 0 {
		t.Fatal("Linux root and namespace capabilities required")
	}
	packageRoot := os.Getenv("BOSUN_UFW_PACKAGE_ROOT")
	if packageRoot != "" {
		var err error
		packageRoot, err = filepath.EvalSymlinks(packageRoot)
		if err != nil || !filepath.IsAbs(packageRoot) {
			t.Fatal("BOSUN_UFW_PACKAGE_ROOT must be an existing absolute package extraction directory")
		}
		t.Setenv("PATH", filepath.Join(packageRoot, "usr/sbin")+":"+os.Getenv("PATH"))
		t.Setenv("PYTHONPATH", filepath.Join(packageRoot, "usr/lib/python3/dist-packages"))
	}
	for _, name := range []string{"unshare", "nsenter", "mount", "cp", "ip", "nft", "ufw", "iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save", "ip6tables-restore", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("required tool unavailable: %s", name)
		}
	}
	if os.Getenv("BOSUN_WG_FIREWALL_CHILD") != "1" {
		fixtureRoot, err := os.MkdirTemp("", "bosun-wg-ufw-")
		if err != nil {
			t.Fatal(err)
		}
		// Cleanup runs only in the parent mount namespace. Never recursively
		// remove the child's lower bind mounts: they expose host directories.
		t.Cleanup(func() { _ = os.RemoveAll(fixtureRoot) })
		ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "unshare", "--mount", "--net", "--propagation", "private", os.Args[0], "-test.run=^TestUFWForwardingLinux$", "-test.v", "-test.timeout=165s")
		cmd.Env = append(os.Environ(), "BOSUN_WG_FIREWALL_CHILD=1", "BOSUN_WG_PARENT_NET="+namespace(t, "self", "net"), "BOSUN_WG_PARENT_MNT="+namespace(t, "self", "mnt"), "BOSUN_WG_FIXTURE_ROOT="+fixtureRoot)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated UFW fixture failed: %v\n%s", err, out)
		}
		t.Log(string(out))
		return
	}
	for _, kind := range []string{"net", "mnt"} {
		current, host := namespace(t, "self", kind), namespace(t, "1", kind)
		parent := os.Getenv("BOSUN_WG_PARENT_" + strings.ToUpper(kind))
		if parent == "" || current == host || current == parent {
			t.Fatalf("refusing nonisolated %s namespace", kind)
		}
	}
	run := func(pid int, stdin, name string, args ...string) string {
		t.Helper()
		if pid != 0 {
			args = append([]string{"-t", strconv.Itoa(pid), "-n", name}, args...)
			name = "nsenter"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated %s failed: %v\n%s", name, err, out)
		}
		return string(out)
	}
	root := os.Getenv("BOSUN_WG_FIXTURE_ROOT")
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "bosun-wg-ufw-") {
		t.Fatal("parent-created fixture directory required")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("fixture directory must be empty")
	}
	write := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A private parent view can introduce an absent /lib/ufw or /etc/ufw
	// without ever mkdir'ing in the host filesystem. All unaffected entries
	// resolve through a private bind of the original parent directory.
	privateView := func(parent string, replacements map[string]string) {
		t.Helper()
		resolved, err := filepath.EvalSymlinks(parent)
		if err != nil {
			t.Fatal(err)
		}
		base, err := os.MkdirTemp(root, "mount-view-")
		if err != nil {
			t.Fatal(err)
		}
		lower, view := filepath.Join(base, "lower"), filepath.Join(base, "view")
		for _, p := range []string{lower, view} {
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
		}
		run(0, "", "mount", "--bind", resolved, lower)
		entries, err := os.ReadDir(lower)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if _, replace := replacements[entry.Name()]; replace {
				continue
			}
			if err := os.Symlink(filepath.Join(lower, entry.Name()), filepath.Join(view, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
		for name, source := range replacements {
			if filepath.Base(name) != name {
				t.Fatal("invalid private mount entry")
			}
			if err := os.Symlink(source, filepath.Join(view, name)); err != nil {
				t.Fatal(err)
			}
		}
		run(0, "", "mount", "--bind", view, resolved)
	}
	// Empty private directories exclude administrator before.init/after.init,
	// arbitrary sysctl files and optional service hooks from the host.
	privateUFW, privateDefault := filepath.Join(root, "ufw"), filepath.Join(root, "default")
	for _, dir := range []string{privateUFW, privateDefault} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	privateView("/etc", map[string]string{"ufw": privateUFW, "default": privateDefault})
	lib := "/lib/ufw"
	if packageRoot != "" {
		lib = filepath.Join(packageRoot, "lib/ufw")
		if _, err := os.Stat(lib); err != nil {
			lib = filepath.Join(packageRoot, "usr/lib/ufw")
		}
		if _, err := os.Stat(filepath.Join(lib, "ufw-init")); err != nil {
			t.Fatal("package ufw-init unavailable")
		}
		privateView("/usr/share", map[string]string{"ufw": filepath.Join(packageRoot, "usr/share/ufw")})
	}
	// Some UFW versions keep locks or generated state below /lib/ufw rather
	// than /run. Copy it privately even when using an installed host package.
	privateLib := filepath.Join(root, "libufw")
	if err := os.Mkdir(privateLib, 0700); err != nil {
		t.Fatal(err)
	}
	run(0, "", "cp", "-a", lib+"/.", privateLib)
	privateView("/lib", map[string]string{"ufw": privateLib})
	// UFW itself uses an absolute iptables directory; expose PATH-resolved
	// extracted tools at those paths inside this mount namespace only. Keep
	// LD_LIBRARY_PATH inherited for unpacked libxtables/libnftnl dependencies.
	iptablesDir := strings.TrimSpace(run(0, "", "python3", "-c", "import ufw.common; print(ufw.common.iptables_dir)"))
	switch iptablesDir {
	case "/sbin", "/usr/sbin", "/bin", "/usr/bin":
	default:
		t.Fatal("unsupported package iptables directory")
	}
	mapped := map[string]bool{}
	for _, parent := range []string{iptablesDir, "/sbin", "/usr/sbin"} {
		resolved, err := filepath.EvalSymlinks(parent)
		if err != nil {
			t.Fatal(err)
		}
		if mapped[resolved] {
			continue
		}
		mapped[resolved] = true
		replacements := map[string]string{}
		for _, name := range []string{"ufw", "iptables", "iptables-save", "iptables-restore", "ip6tables", "ip6tables-save", "ip6tables-restore"} {
			source, err := exec.LookPath(name)
			if err != nil {
				t.Fatal(err)
			}
			source, err = filepath.Abs(source)
			if err != nil {
				t.Fatal(err)
			}
			sourceDir, _ := filepath.EvalSymlinks(filepath.Dir(source))
			if sourceDir != resolved {
				replacements[name] = source
			}
		}
		if len(replacements) > 0 {
			privateView(resolved, replacements)
		}
	}
	// UFW checks argv[0]'s ancestors and warns about /tmp even when its
	// extraction root is private. Invoke the private standard-path alias so
	// package staging does not alter the real command's status output.
	t.Setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin:"+os.Getenv("PATH"))
	for target, source := range map[string]string{"/etc/ufw": privateUFW, "/etc/default": privateDefault} {
		a, e1 := os.Stat(source)
		b, e2 := os.Stat(target)
		if e1 != nil || e2 != nil || !os.SameFile(a, b) {
			t.Fatal("private UFW configuration mount verification failed")
		}
	}
	// Isolate UFW locks and host firewalld's D-Bus socket as well.
	run(0, "", "mount", "-t", "tmpfs", "-o", "mode=0755,nosuid,nodev", "wg-test-run", "/run")
	write("/etc/default/ufw", "IPV6=no\nDEFAULT_INPUT_POLICY=DROP\nDEFAULT_OUTPUT_POLICY=ACCEPT\nDEFAULT_FORWARD_POLICY=DROP\nDEFAULT_APPLICATION_POLICY=SKIP\nMANAGE_BUILTINS=no\nIPT_SYSCTL=/etc/ufw/sysctl.conf\nIPT_MODULES=\"\"\n")
	write("/etc/ufw/ufw.conf", "ENABLED=no\nLOGLEVEL=off\n")
	write("/etc/ufw/sysctl.conf", "net.ipv4.ip_forward=1\n")
	if err := os.Mkdir("/etc/ufw/applications.d", 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"before.rules", "after.rules", "before6.rules", "after6.rules", "user.rules", "user6.rules"} {
		var data []byte
		var err error
		for _, base := range []string{"/usr/share/ufw", "/usr/share/ufw/iptables"} {
			data, err = os.ReadFile(filepath.Join(base, name))
			if err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("packaged UFW rule template unavailable: %s", name)
		}
		write(filepath.Join("/etc/ufw", name), string(data))
	}
	// Include packaged empty user/user6 templates: dpkg extraction deliberately
	// skips maintscripts, and UFW requires both files to exist before startup.
	run(0, "", "ufw", "--force", "enable")
	run(0, "", "ufw", "logging", "off")
	run(0, "", "ufw", "default", "deny", "routed")
	if !strings.Contains(run(0, "", "ufw", "status", "verbose"), "deny (routed)") {
		t.Fatal("fixture did not establish default deny routed")
	}
	child := func() int {
		t.Helper()
		cmd := exec.Command("unshare", "--net", "sleep", "160")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		pid := cmd.Process.Pid
		self := namespace(t, "self", "net")
		for i := 0; i < 100; i++ {
			ns, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
			if ns != "" && ns != self {
				return pid
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("child network namespace did not become ready")
		return 0
	}
	client, target := child(), child()
	run(0, "", "ip", "link", "set", "lo", "up")
	for _, p := range []struct {
		pid                               int
		local, peer, address, peerAddress string
	}{{client, "bwg1", "client0", "10.10.0.6/30", "10.10.0.5/30"}, {target, "wan0", "target0", "198.51.100.1/24", "198.51.100.20/24"}} {
		run(0, "", "ip", "link", "add", p.local, "type", "veth", "peer", "name", p.peer)
		run(0, "", "ip", "link", "set", p.peer, "netns", strconv.Itoa(p.pid))
		run(0, "", "ip", "addr", "add", p.address, "dev", p.local)
		run(0, "", "ip", "link", "set", p.local, "up")
		run(p.pid, "", "ip", "link", "set", "lo", "up")
		run(p.pid, "", "ip", "addr", "add", p.peerAddress, "dev", p.peer)
		run(p.pid, "", "ip", "link", "set", p.peer, "up")
		run(p.pid, "", "ip", "route", "add", "default", "via", strings.Split(p.address, "/")[0])
	}
	run(0, "", "ip", "route", "add", "default", "via", "198.51.100.20", "dev", "wan0")
	// An earlier nft ACCEPT is deliberately insufficient while UFW still
	// denies forwarding, reproducing the distinct-netfilter-base-chain issue.
	run(0, "table inet wg_test {\n chain forward {\n type filter hook forward priority -10; policy accept;\n iifname \"bwg1\" ip saddr 10.10.0.5 tcp dport 18080 accept\n oifname \"bwg1\" ip daddr 10.10.0.5 ct state established accept\n }\n}\n", "nft", "-f", "-")
	run(0, "", "iptables", "-w", "2", "-N", "BOSUN_TEST_SENTINEL")
	run(0, "", "iptables", "-w", "2", "-A", "BOSUN_TEST_SENTINEL", "-s", "203.0.113.30/32", "-j", "RETURN")
	sentinelBefore := run(0, "", "iptables", "-w", "2", "-S", "BOSUN_TEST_SENTINEL")
	server := exec.Command("nsenter", "-t", strconv.Itoa(target), "-n", "python3", "-u", "-c", ufwHTTPServer)
	stdout, err := server.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Process.Kill(); _ = server.Wait() })
	ready := make(chan bool, 1)
	go func() { scanner := bufio.NewScanner(stdout); ready <- scanner.Scan() && scanner.Text() == "ready" }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("HTTP fixture failed to start")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP fixture startup timed out")
	}
	probe := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "nsenter", "-t", strconv.Itoa(client), "-n", "python3", "-c", ufwHTTPClient)
		out, err := cmd.CombinedOutput()
		if want != (err == nil && strings.TrimSpace(string(out)) == "forward-ok") {
			t.Fatalf("forwarding wanted %v: %v %s", want, err, out)
		}
	}
	// Verify server reachability independently of the forwarded client.
	if out := run(target, "", "python3", "-c", ufwHTTPClient); strings.TrimSpace(out) != "forward-ok" {
		t.Fatal(out)
	}
	probe(false)
	ctx := context.Background()
	t.Logf("isolated UFW status before manager (stdout+stderr):\n%s", run(0, "", "ufw", "status"))
	m := &Manager{StateFile: filepath.Join(root, "wg-firewall.json")}
	links := []spec.WireGuardLink{{Slot: 1, Exit: true}}
	if err := m.Apply(ctx, links); err != nil {
		t.Fatalf("real UFW apply: %v (%+v)", err, m.Status())
	}
	if len(m.Status().Rules) != 4 {
		t.Fatal(m.Status())
	}
	probe(true)
	commandsBefore := run(0, "", "ufw", "show", "added")
	if err := m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if commandsBefore != run(0, "", "ufw", "show", "added") {
		t.Fatal("unchanged refresh altered owned rules")
	}
	// UFW status and show added continue to show the rule after direct kernel
	// deletion. Only the actual iptables tuple can detect this failure.
	var liveArgs []string
	for _, line := range strings.Split(run(0, "", "iptables", "-w", "2", "-S", "ufw-user-forward"), "\n") {
		r, ok := parseLiveUFW(line, "ufw-user-forward")
		if ok && r.In == "bwg1" && r.Protocol == "tcp" {
			liveArgs = strings.Fields(line)
			break
		}
	}
	if len(liveArgs) == 0 {
		t.Fatal("managed live forward tuple missing")
	}
	liveArgs[0] = "-D"
	run(0, "", "iptables", append([]string{"-w", "2"}, liveArgs...)...)
	if commandsBefore != run(0, "", "ufw", "show", "added") {
		t.Fatal("kernel deletion changed persistent configuration")
	}
	if err := m.Refresh(ctx); err == nil || m.Status().State != "error" {
		t.Fatal("missing kernel rule reported synced")
	}
	probe(false)
	liveArgs[0] = "-A"
	run(0, "", "iptables", append([]string{"-w", "2"}, liveArgs...)...)
	if err := m.Apply(ctx, links); err != nil {
		t.Fatal(err)
	}
	restarted := &Manager{StateFile: m.StateFile}
	if err := restarted.Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	probe(false)
	if strings.Contains(run(0, "", "ufw", "show", "added"), "bosun-wg-") {
		t.Fatal("restart left owned rules")
	}
	// A preexisting equivalent allowance must remain byte-for-byte unchanged
	// and must never gain our ownership marker.
	manualArgs := []string{"route", "allow", "in", "on", "bwg1", "out", "on", "wan0", "proto", "tcp", "from", "10.10.0.5", "to", "any", "comment", "operator-forward"}
	run(0, "", "ufw", manualArgs...)
	run(0, "", "ufw", "allow", "18443/tcp", "comment", "operator-listener")
	run(0, "", "ufw", "deny", "19443/tcp", "comment", "operator-deny")
	run(0, "", "ufw", "allow", "log", "19444/tcp", "comment", "operator-log")
	manualBefore := run(0, "", "ufw", "show", "added")
	if err := restarted.Apply(ctx, links); err != nil {
		t.Fatal(err)
	}
	if restarted.Status().State != "external" {
		t.Fatal(restarted.Status())
	}
	probe(true)
	if err := (&Manager{StateFile: m.StateFile}).Apply(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if after := run(0, "", "ufw", "show", "added"); after != manualBefore {
		t.Fatal("manual rules changed during ownership reconciliation")
	}
	if sentinelBefore != run(0, "", "iptables", "-w", "2", "-S", "BOSUN_TEST_SENTINEL") {
		t.Fatal("UFW reconciliation changed an independent filter chain")
	}
	run(0, "", "nft", "list", "table", "inet", "wg_test")
	probe(true) // UFW's standard established/reply rule covers the response.
	deleteArgs := append([]string{"route", "delete"}, manualArgs[1:]...)
	run(0, "", "ufw", deleteArgs...)
	probe(false)
	for _, action := range []string{"deny", "allow"} {
		logged := append([]string{"route", action}, manualArgs[2:8]...)
		logged = append(logged, "log")
		logged = append(logged, manualArgs[8:]...)
		logged[len(logged)-1] = "operator-logged-" + action
		run(0, "", "ufw", logged...)
		before := run(0, "", "ufw", "show", "added")
		if err := (&Manager{StateFile: m.StateFile}).Apply(ctx, links); err == nil {
			t.Fatal("logged operator rule unexpectedly accepted")
		}
		if after := run(0, "", "ufw", "show", "added"); after != before {
			t.Fatal("logged operator rule changed")
		}
		run(0, "", "ufw", append([]string{"route", "delete"}, logged[1:]...)...)
	}
	t.Log("real UFW: deny -> owned allow -> restart cleanup deny; manual equivalent retained; early nft ACCEPT did not bypass UFW")
}

func namespace(t *testing.T, process, kind string) string {
	t.Helper()
	ns, err := os.Readlink("/proc/" + process + "/ns/" + kind)
	if err != nil || ns == "" {
		t.Fatalf("namespace identity unavailable: %s", kind)
	}
	return ns
}

const ufwHTTPServer = `
import socket,time
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('198.51.100.20',18080));s.listen(16);s.settimeout(1)
print('ready',flush=True)
deadline=time.monotonic()+140
while time.monotonic()<deadline:
 try:c,a=s.accept()
 except socket.timeout:continue
 try:
  c.settimeout(2);c.recv(4096)
  c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nforward-ok')
 finally:c.close()
`

const ufwHTTPClient = `
import socket
with socket.create_connection(('198.51.100.20',18080),timeout=1) as s:
 s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n')
 data=b''
 while True:
  b=s.recv(4096)
  if not b:break
  data+=b
 assert data.endswith(b'forward-ok'),data
 print('forward-ok')
`
