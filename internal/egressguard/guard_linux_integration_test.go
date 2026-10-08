package egressguard

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"os"
	"os/exec"
	"testing"
)

func TestGuardLinuxScopedConnections(t *testing.T) {
	if os.Getenv("BOSUN_NFT_TEST") != "1" {
		t.Skip("set BOSUN_NFT_TEST=1 for isolated Linux nft integration")
	}
	opt := Options{ProtectedPorts: []int{9101}, Upstreams: []spec.EgressUpstream{{CIDR: "10.10.0.2", Protocol: "tcp", Port: 1080}, {CIDR: "2001:db8::10", Protocol: "udp", Port: 1080}, {CIDR: "127.0.0.1", Protocol: "tcp", Port: 9101}}}
	script := Script(65534, opt)
	opt.Disabled = true
	disabled := Script(65534, opt)
	cmd := exec.Command("unshare", "-n", "python3", "-c", guardIntegrationPython)
	cmd.Env = append(os.Environ(), "NFT_SCRIPT="+script, "NFT_DISABLED="+disabled)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated egress: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const guardIntegrationPython = `
import os,socket,threading,subprocess as s
sockets=[]
def run(*args,**kwargs):return s.run(args,check=True,capture_output=True,text=True,**kwargs)
run('ip','link','set','lo','up')
run('ip','addr','add','10.10.0.2/32','dev','lo')
run('ip','-6','addr','add','2001:db8::10/128','dev','lo','nodad')
def serve(sock,udp):
 while True:
  if udp:data,addr=sock.recvfrom(1024);sock.sendto(data,addr)
  else:conn,addr=sock.accept();conn.sendall(conn.recv(1024));conn.close()
for family,addr,port in [(socket.AF_INET,'10.10.0.2',1080),(socket.AF_INET,'10.10.0.2',1081),(socket.AF_INET6,'2001:db8::10',1080),(socket.AF_INET,'127.0.0.1',9101)]:
 for udp in [False,True]:
  sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);sock.bind((addr,port))
  if not udp:sock.listen()
  sockets.append(sock);threading.Thread(target=serve,args=(sock,udp),daemon=True).start()
probe=r'''
import os,socket,sys
os.setgid(65534);os.setuid(65534)
family,addr,port,udp,expected=sys.argv[1:]
sock=socket.socket(int(family),socket.SOCK_DGRAM if udp=='1' else socket.SOCK_STREAM);sock.settimeout(.4)
try:
 sock.connect((addr,int(port)));sock.send(b'ok');actual=sock.recv(2)==b'ok'
except OSError:actual=False
assert actual==(expected=='1'),(addr,port,udp,expected,actual)
'''
def check(addr,port,udp,want):run('python3','-c',probe,str(socket.AF_INET6 if ':' in addr else socket.AF_INET),addr,str(port),'1' if udp else '0','1' if want else '0')
run('nft','-c','-f','-',input=os.environ['NFT_SCRIPT'])
run('nft','-f','-',input=os.environ['NFT_SCRIPT'])
check('10.10.0.2',1080,False,True)
check('10.10.0.2',1080,True,False)
check('10.10.0.2',1081,False,False)
check('2001:db8::10',1080,True,True)
check('2001:db8::10',1080,False,False)
check('127.0.0.1',9101,False,False)
run('nft','-f','-',input='delete table inet bosun_egress\n'+os.environ['NFT_DISABLED'])
check('10.10.0.2',1081,False,True)
check('127.0.0.1',9101,False,False)
run('nft','-f','-',input='delete table inet bosun_egress\n'+os.environ['NFT_SCRIPT'])
check('10.10.0.2',1081,False,False)
print('scoped TCP/UDP IPv4/IPv6 exceptions, disable/re-enable, root-only API protection passed')
`
