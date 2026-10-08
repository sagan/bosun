package forward

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"os"
	"os/exec"
	"testing"
)

// Run only as root on Linux with nft/ip/nsenter/python3. Everything, including
// child network namespaces and sysctls, lives below an unshare-created namespace.
func TestNFTLinuxDualStackRelay(t *testing.T) {
	if os.Getenv("BOSUN_NFT_TEST") != "1" {
		t.Skip("set BOSUN_NFT_TEST=1 for isolated Linux nft integration")
	}
	rules := []spec.Forward{{Tag: "v4", Listen: "192.0.2.1", Port: 21081, Protocol: "both", Target: "198.51.100.20:1081", Backend: "nft"}, {Tag: "v6", Listen: "2001:db8:1::1", Port: 21081, Protocol: "both", Target: "[2001:db8:2::20]:1081", Backend: "nft"}}
	script := renderNFT(rules, map[string]nftTarget{"v4": {IP: "198.51.100.20", Port: 1081}, "v6": {IP: "2001:db8:2::20", Port: 1081}})
	cmd := exec.Command("unshare", "-n", "python3", "-c", nftIntegrationPython)
	cmd.Env = append(os.Environ(), "NFT_SCRIPT="+script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated nft: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const nftIntegrationPython = `
import os, subprocess as s, time
children=[]
def run(*args, **kwargs): return s.run(args,check=True,capture_output=True,text=True,**kwargs)
def ns(pid,*args,**kwargs):return run('nsenter','-t',str(pid),'-n',*args,**kwargs)
try:
 for _ in range(2):
  p=s.Popen(['unshare','-n','sleep','90']);children.append(p)
 time.sleep(.2)
 client,target=[p.pid for p in children]
 run('ip','link','set','lo','up')
 for peer,pid,net,local,remote in [('cl',client,1,'192.0.2.1','192.0.2.10'),('tg',target,2,'198.51.100.1','198.51.100.20')]:
  run('ip','link','add',peer,'type','veth','peer','name',peer+'p')
  run('ip','link','set',peer+'p','netns',str(pid))
  run('ip','addr','add',local+'/24','dev',peer)
  run('ip','-6','addr','add',f'2001:db8:{net}::1/64','dev',peer,'nodad')
  run('ip','link','set',peer,'up')
  ns(pid,'ip','link','set','lo','up');ns(pid,'ip','link','set',peer+'p','up')
  ns(pid,'ip','addr','add',remote+'/24','dev',peer+'p')
  ns(pid,'ip','-6','addr','add',f'2001:db8:{net}::20/64','dev',peer+'p','nodad')
  ns(pid,'ip','route','add','default','via',local)
  ns(pid,'ip','-6','route','add','default','via',f'2001:db8:{net}::1')
 run('sysctl','-q','-w','net.ipv4.ip_forward=1','net.ipv6.conf.all.forwarding=1')
 run('nft','-c','-f','-',input=os.environ['NFT_SCRIPT'])
 run('nft','-f','-',input=os.environ['NFT_SCRIPT'])
 server=r'''
import socket,threading,time
sockets=[]
def serve(sock,udp):
 while True:
  if udp:
   data,addr=sock.recvfrom(1024);sock.sendto(data,addr)
  else:
   conn,addr=sock.accept();conn.sendall(conn.recv(1024));conn.close()
for family,addr in [(socket.AF_INET,'198.51.100.20'),(socket.AF_INET6,'2001:db8:2::20')]:
 for udp in [False,True]:
  sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);sock.bind((addr,1081))
  if not udp:sock.listen()
  sockets.append(sock);threading.Thread(target=serve,args=(sock,udp),daemon=True).start()
print('ready',flush=True);time.sleep(60)
'''
 p=s.Popen(['nsenter','-t',str(target),'-n','python3','-u','-c',server],stdout=s.PIPE,text=True);children.append(p)
 assert p.stdout.readline().strip()=='ready'
 clientcode=r'''
import socket
for family,addr in [(socket.AF_INET,'192.0.2.1'),(socket.AF_INET6,'2001:db8:1::1')]:
 for udp in [False,True]:
  sock=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);sock.settimeout(2);sock.connect((addr,21081));sock.send(b'echo');assert sock.recv(4)==b'echo';sock.close()
  print('passed',family,'udp' if udp else 'tcp')
'''
 print(ns(client,'python3','-c',clientcode).stdout)
finally:
 for p in reversed(children):
  p.terminate()
 for p in children:p.wait()
`
