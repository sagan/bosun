package privateintegration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/core/singbox"
	"github.com/zeptop-dev/bosun/internal/core/xray"
	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Real fixed-version binaries + actual nft/UID/SO_MARK, in an isolated network
// namespace. No host firewall, routes, sysctls or running services are modified.
func TestPrivateAccessLinuxCores(t *testing.T) {
	if os.Getenv("BOSUN_NFT_TEST") != "1" {
		t.Skip("set BOSUN_NFT_TEST=1 and both BOSUN_*_TEST_BINARY paths on Linux")
	}
	if os.Getenv("BOSUN_TEST_DOWNLOAD_CORES") == "1" {
		installer := coreinstall.New(t.TempDir(), slog.Default())
		for _, name := range []string{"singbox", "xray"} {
			env := "BOSUN_" + strings.ToUpper(name) + "_TEST_BINARY"
			if os.Getenv(env) != "" {
				continue
			}
			release, ok := coreinstall.Tested(name)
			if !ok {
				t.Fatalf("no tested %s release", name)
			}
			binary, err := installer.Ensure(context.Background(), name, release.Version)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(env, binary)
		}
	}
	for _, kind := range []string{"singbox", "singbox-shadowtls", "xray", "xray-reverse"} {
		t.Run(kind, func(t *testing.T) {
			binary := os.Getenv("BOSUN_SINGBOX_TEST_BINARY")
			if !strings.HasPrefix(kind, "singbox") {
				binary = os.Getenv("BOSUN_XRAY_TEST_BINARY")
			}
			if binary == "" {
				t.Fatal("missing real core binary")
			}
			dir := t.TempDir()
			if err := os.Chmod(dir, 0755); err != nil {
				t.Fatal(err)
			}
			// Go's top-level temporary test directory must also be traversable.
			if err := os.Chmod(filepath.Dir(dir), 0755); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(dir, "core")
			if err = os.WriteFile(bin, data, 0755); err != nil {
				t.Fatal(err)
			}
			var adapter core.Core
			if !strings.HasPrefix(kind, "singbox") {
				adapter, err = xray.New(xray.Options{Binary: bin, WorkDir: dir, APIListen: "127.0.0.1:19102", LogLevel: "debug"}, slog.Default())
			} else {
				adapter, err = singbox.New(singbox.Options{Binary: bin, WorkDir: dir, StatsListen: "127.0.0.1:19102"}, slog.Default())
			}
			if err != nil {
				t.Fatal(err)
			}
			policy := &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2", PortStart: 18080}, {CIDR: "fd42::2", PortStart: 18080}, {CIDR: "100.64.0.0/10"}, {CIDR: "fd00:ec2::/64"}, {CIDR: "10.10.0.2", Protocol: "tcp", PortStart: 18082}}}
			inbounds := []spec.Inbound{{Tag: "allowed", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 30200, PrivateAccess: policy}, {Tag: "denied", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 30201}}
			node := &spec.Node{Inbounds: inbounds, UserSpeedLimitMbps: 2, DNS: []string{"127.0.0.1"}}
			var transits []string
			var clientConfig string
			if kind == "singbox-shadowtls" {
				clientIns, clientOuts, clientRoutes := []any{}, []any{}, []any{}
				for i := range node.Inbounds {
					ib := &node.Inbounds[i]
					ib.Protocol = spec.Shadowsocks
					ib.Cipher = "2022-blake3-aes-128-gcm"
					ib.ServerKey = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
					ib.ShadowTLS = &spec.ShadowTLS{Handshake: "127.0.0.1:18443", StrictMode: true}
					ib.Port = 31300 + i
					clientIns = append(clientIns, map[string]any{"type": "vless", "tag": ib.Tag, "listen": "127.0.0.1", "listen_port": 30200 + i, "users": []any{map[string]any{"uuid": "11111111-1111-4111-8111-111111111111"}}})
					clientOuts = append(clientOuts, map[string]any{"type": "shadowsocks", "tag": "ss-" + ib.Tag, "server": "127.0.0.1", "server_port": ib.Port, "method": ib.Cipher, "udp_over_tcp": true, "password": ib.ServerKey + ":" + base64.StdEncoding.EncodeToString([]byte("11111111-1111-4111-8111-111111111111"[:16])), "detour": "st-" + ib.Tag}, map[string]any{"type": "shadowtls", "tag": "st-" + ib.Tag, "server": "127.0.0.1", "server_port": ib.Port, "version": 3, "password": spec.ShadowTLSUserKey("11111111-1111-4111-8111-111111111111"), "tls": map[string]any{"enabled": true, "server_name": "example.com", "insecure": true}})
					clientRoutes = append(clientRoutes, map[string]any{"inbound": []string{ib.Tag}, "outbound": "ss-" + ib.Tag})
				}
				b, _ := json.Marshal(map[string]any{"log": map[string]any{"level": "warn"}, "inbounds": clientIns, "outbounds": clientOuts, "route": map[string]any{"rules": clientRoutes}})
				clientConfig = filepath.Join(dir, "shadow-client.json")
				if err = os.WriteFile(clientConfig, b, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "xray-reverse" {
				node.Inbounds = nil
				node.UserSpeedLimitMbps = 0
				for i, ib := range inbounds {
					id := ib.Tag
					ib.Reverse = &spec.ReverseInbound{ID: id}
					ib.Core = "xray"
					control := spec.Inbound{Tag: "control-" + id, Protocol: spec.VLESS, Listen: "127.0.0.1", Port: 31200 + i, Core: "xray", Reverse: &spec.ReverseInbound{ID: id, Receiver: true, UUID: "22222222-2222-4222-8222-222222222222"}}
					aNode := &spec.Node{Inbounds: []spec.Inbound{ib, control}}
					a, err := xray.New(xray.Options{Binary: bin, WorkDir: filepath.Join(dir, id), APIListen: fmt.Sprintf("127.0.0.1:%d", 19200+i), LogLevel: "warning"}, slog.Default())
					if err != nil {
						t.Fatal(err)
					}
					bundle, err := a.Render(aNode, aNode.Inbounds, []spec.User{{ID: 1, Name: "user", UUID: "11111111-1111-4111-8111-111111111111"}})
					if err != nil {
						t.Fatal(err)
					}
					config := filepath.Join(dir, id+".json")
					if err = os.WriteFile(config, bundle.Files[bundle.Main], 0644); err != nil {
						t.Fatal(err)
					}
					transits = append(transits, config)
					node.ReverseClients = append(node.ReverseClients, spec.ReverseClient{ID: id, Host: "127.0.0.1", Port: 31200 + i, UUID: control.Reverse.UUID, PrivateAccess: ib.PrivateAccess})
				}
			}
			users := []spec.User{{ID: 1, Name: "user", UUID: "11111111-1111-4111-8111-111111111111"}}
			bundle, err := adapter.Render(node, node.Inbounds, users)
			if err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(dir, "config.json")
			if err = os.WriteFile(config, bundle.Files[bundle.Main], 0644); err != nil {
				t.Fatal(err)
			}
			grants, err := node.PrivateGrants(users)
			if err != nil {
				t.Fatal(err)
			}
			opt := egressguard.Options{PrivateGrants: grants, LoopbackPorts: []int{53}, ProtectedPorts: []int{19102}}
			if kind == "xray-reverse" {
				opt.Upstreams = []spec.EgressUpstream{{CIDR: "127.0.0.1", Protocol: "tcp", Port: 31200}, {CIDR: "127.0.0.1", Protocol: "tcp", Port: 31201}}
			}
			if kind == "singbox-shadowtls" {
				opt.LoopbackPorts = append(opt.LoopbackPorts, 18443)
			}
			self, _ := os.Executable()
			marks := []int64{}
			for _, grant := range grants {
				if grant.UserID == 1 {
					marks = append(marks, grant.Mark)
				}
			}
			input, _ := json.Marshal(map[string]any{"helper": self, "marks": marks, "shadow_client": clientConfig, "kind": kind, "transits": transits, "binary": bin, "config": config, "guard": egressguard.Script(65534, opt), "revoked": egressguard.Script(65534, egressguard.Options{Upstreams: opt.Upstreams, LoopbackPorts: []int{53}, ProtectedPorts: []int{19102}})})
			cmd := exec.Command("unshare", "-n", "python3", "-c", privateCorePython, string(input))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("real private access: %v\n%s", err, out)
			} else {
				t.Log(string(out))
			}
		})
	}
}

const privateCorePython = `
import json,sys,os,socket,struct,threading,subprocess as s,time,uuid,ssl,re
c=json.loads(sys.argv[1]); sockets=[]
def run(*args,**kw):
 r=s.run(args,capture_output=True,text=True,**kw)
 if r.returncode:raise RuntimeError(str(args)+'\n'+r.stdout+'\n'+r.stderr)
 return r
run('ip','link','set','lo','up')
for addr in ['10.10.0.2/32','10.10.0.3/32','fd42::2/128','192.0.0.9/32','100.100.100.200/32','fd00:ec2::254/128']:
 run('ip','addr','add',addr,'dev','lo')
def check_shaped():
 # Older iproute2 builds mix non-JSON class output into tc -j -s.
 # Read the stable text counter block for the real subscriber HTB class.
 stats=run('tc','-s','class','show','dev','lo').stdout
 block=re.search(r'(?ms)^class htb 1:2\b.*?(?=^class |\Z)',stats)
 count=re.search(r'\bSent (\d+) bytes',block.group(0)) if block else None
 assert count and int(count.group(1))>0,stats
def serve(sock,udp):
 while True:
  if udp:
   data,addr=sock.recvfrom(65535);sock.sendto(data,addr)
  else:
   conn,_=sock.accept()
   def echo(conn):
    try:
     while True:
      data=conn.recv(65535)
      if not data:break
      conn.sendall(data)
    except OSError:pass
    conn.close()
   threading.Thread(target=echo,args=(conn,),daemon=True).start()
for addr in ['10.10.0.2','10.10.0.3','fd42::2','192.0.0.9','100.100.100.200','fd00:ec2::254']:
 for port in [18080,18081,18082]:
  for udp in [False,True]:
   sock=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
   sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);sock.bind((addr,port))
   if not udp:sock.listen()
   sockets.append(sock);threading.Thread(target=serve,args=(sock,udp),daemon=True).start()
# A tiny isolated DNS server; names resolving into and outside the allowlist.
dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('127.0.0.1',53));sockets.append(dns)
def resolve():
 while True:
  data,peer=dns.recvfrom(4096);i=12;labels=[]
  while data[i]:n=data[i];labels.append(data[i+1:i+1+n].decode());i+=n+1
  end=i+5;qtype=struct.unpack('!H',data[i+1:i+3])[0]
  addr='10.10.0.3' if labels[0]=='denied' else '10.10.0.2'
  ans=b'' if qtype!=1 else b'\xc0\x0c\x00\x01\x00\x01'+struct.pack('!IH',1,4)+socket.inet_aton(addr)
  dns.sendto(data[:2]+b'\x81\x80'+struct.pack('!HHHH',1,int(bool(ans)),0,0)+data[12:end]+ans,peer)
threading.Thread(target=resolve,daemon=True).start()
if c['shadow_client']:
 cert=c['config']+'.crt';key=c['config']+'.key'
 run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=example.com')
 tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.minimum_version=ssl.TLSVersion.TLSv1_3;tls.load_cert_chain(cert,key)
 listener=socket.socket();listener.bind(('127.0.0.1',18443));listener.listen();sockets.append(listener)
 def fallback():
  while True:
   conn,_=listener.accept()
   try:conn=tls.wrap_socket(conn,server_side=True);conn.recv(4096)
   except (OSError,ssl.SSLError):pass
   conn.close()
 threading.Thread(target=fallback,daemon=True).start()
run('nft','-c','-f','-',input=c['guard']);run('nft','-f','-',input=c['guard'])
def helper(mode):
 env=dict(os.environ,BOSUN_PRIVATE_HELPER=mode,BOSUN_PRIVATE_FIXTURE=json.dumps(c))
 run(c['helper'],'-test.run=^TestPrivateFixtureHelper$',env=env)
if c['marks']:helper('shape')
command=[c['binary'],'run','-c',c['config']] if c['kind'].startswith('singbox') else [c['binary'],'run','-config',c['config']]
check=[c['binary'],'check','-c',c['config']] if c['kind'].startswith('singbox') else [c['binary'],'run','-test','-config',c['config']]
run(*check)
log=open(c['config']+'.log','w+')
transits=[s.Popen([c['binary'],'run','-config',config],stdout=log,stderr=log) for config in c['transits'] or []]
if c['shadow_client']:transits.append(s.Popen([c['binary'],'run','-c',c['shadow_client']],stdout=log,stderr=log))
p=s.Popen(['setpriv','--reuid=65534','--regid=65534','--clear-groups','--inh-caps=+net_admin,+net_bind_service','--ambient-caps=+net_admin,+net_bind_service']+command,stdout=log,stderr=log)
def exact(sock,n):
 b=b''
 while len(b)<n:
  part=sock.recv(n-len(b))
  if not part:raise OSError('closed')
  b+=part
 return b
def connect(ib,addr,port,udp=False):
 sock=socket.create_connection(('127.0.0.1',ib),1);sock.settimeout(2.0)
 try:
  if ':' in addr:target=b'\x03'+socket.inet_pton(socket.AF_INET6,addr)
  else:
   try:target=b'\x01'+socket.inet_aton(addr)
   except OSError:target=b'\x02'+bytes([len(addr)])+addr.encode()
  payload=b'ping'
  sock.sendall(b'\x00'+uuid.UUID('11111111-1111-4111-8111-111111111111').bytes+b'\x00'+bytes([2 if udp else 1])+struct.pack('!H',port)+target+(struct.pack('!H',len(payload)) if udp else b'')+payload)
  header=exact(sock,2);exact(sock,header[1])
  if udp:assert struct.unpack('!H',exact(sock,2))[0]==4
  assert exact(sock,4)==payload
  return sock
 except BaseException:sock.close();raise
def probe(ib,addr,port,want,udp=False):
 try:sock=connect(ib,addr,port,udp);sock.close();actual=True
 except (OSError,AssertionError):actual=False
 assert actual==want,(c['kind'],ib,addr,port,udp,'expected',want,'got',actual)
try:
 for _ in range(50):
  try:sock=socket.create_connection(('127.0.0.1',30200),.1);sock.close();break
  except OSError:
   if p.poll() is not None:raise AssertionError('core exited')
   time.sleep(.05)
 if transits:
  for _ in range(20):
   try:sock=connect(30200,'10.10.0.2',18080);sock.close();break
   except (OSError,AssertionError):time.sleep(.25)
  else:raise AssertionError('transport did not connect')
 for udp in [False,True]:
  for addr in ['10.10.0.2','fd42::2','allowed.example.com']:
   probe(30200,addr,18080,True,udp);probe(30201,addr,18080,False,udp)
  if c['marks']:
   check_shaped()
  for addr,port in [('10.10.0.2',18081),('10.10.0.3',18080),('denied.example.com',18080),('127.0.0.1',19102),('100.100.100.200',18080),('fd00:ec2::254',18080)]:probe(30200,addr,port,False,udp)
  probe(30200,'192.0.0.9',18080,True,udp);probe(30201,'192.0.0.9',18080,True,udp)
 probe(30200,'10.10.0.2',18082,True);probe(30200,'10.10.0.2',18082,False,True)
 helper('stats')
 if c['marks']:
  check_shaped()
 tcp=connect(30200,'10.10.0.2',18080);udp=connect(30200,'10.10.0.2',18080,True)
 run('nft','-f','-',input='delete table inet bosun_egress\n'+c['revoked'])
 for sock,payload in [(tcp,b'next'),(udp,b'\x00\x04next')]:
  sock.sendall(payload)
  try:data=sock.recv(100);assert not data,'revoked existing connection still passes'
  except socket.timeout:pass
  sock.close()
 print(c['kind']+': real TCP/UDP IPv4/IPv6, same-user dual inbound, DNS private targets, protocol/port bounds, public egress, control API/metadata isolation, subscriber counters, tc class mapping and established-flow revocation passed')
except BaseException:
 log.flush();log.seek(0);print(log.read()[-12000:]);raise
finally:
 p.terminate()
 try:p.wait(timeout=3)
 except s.TimeoutExpired:p.kill();p.wait()
 for a in transits:a.terminate();a.wait(timeout=3)
 log.close()
`

// Invoked only by the namespace fixture, never against the host network.
func TestPrivateFixtureHelper(t *testing.T) {
	mode := os.Getenv("BOSUN_PRIVATE_HELPER")
	if mode == "" {
		t.Skip("namespace subprocess helper")
	}
	var c struct {
		Kind   string
		Binary string
		Config string
		Marks  []int64
	}
	if err := json.Unmarshal([]byte(os.Getenv("BOSUN_PRIVATE_FIXTURE")), &c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if mode == "shape" {
		s := &shaper.Shaper{Interface: "lo"}
		if err := s.Apply(ctx, []shaper.Limit{{UserID: 1, Mbps: 2, Marks: c.Marks}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	port := 19102
	if c.Kind == "xray-reverse" {
		port = 19200
	}
	var adapter core.Core
	var err error
	if strings.HasPrefix(c.Kind, "singbox") {
		adapter, err = singbox.New(singbox.Options{Binary: c.Binary, WorkDir: filepath.Dir(c.Config), StatsListen: fmt.Sprintf("127.0.0.1:%d", port)}, slog.Default())
	} else {
		adapter, err = xray.New(xray.Options{Binary: c.Binary, WorkDir: filepath.Dir(c.Config), APIListen: fmt.Sprintf("127.0.0.1:%d", port)}, slog.Default())
	}
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Stop(ctx)
	counters, err := adapter.Stats(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	traffic := counters[spec.InboundUser("user", "allowed")]
	if traffic.Up <= 0 || traffic.Down <= 0 {
		t.Fatalf("subscriber accounting missing: %v", counters)
	}
	for name := range counters {
		if strings.HasPrefix(name, "reverse-") {
			t.Fatal("transport identity billed as subscriber")
		}
	}
}
