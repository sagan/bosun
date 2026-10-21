package singbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/internal/coreinstall"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/net/dns/dnsmessage"
)

// Runs without nft, routing changes or elevated privileges. Targets are temporary
// echo services on a local RFC1918 interface; no operator addresses are fixtures.
func TestCoreOnlyRealSingbox(t *testing.T) {
	for _, distribution := range []string{"singbox", "singbox-extended"} {
		t.Run(distribution, func(t *testing.T) {
			binaryPath := os.Getenv("BOSUN_COREONLY_TEST_BINARY")
			if distribution == "singbox-extended" {
				binaryPath = os.Getenv("BOSUN_EXTENDED_TEST_BINARY")
			}
			if binaryPath == "" && os.Getenv("BOSUN_TEST_DOWNLOAD_CORES") == "1" {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				release, ok := coreinstall.Default(distribution)
				if !ok {
					t.Fatal("missing reviewed core")
				}
				var err error
				binaryPath, err = coreinstall.New(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil))).Ensure(ctx, distribution, release.Version)
				if err != nil {
					t.Fatal(err)
				}
			}
			if binaryPath == "" {
				t.Skip("set BOSUN_COREONLY_TEST_BINARY / BOSUN_EXTENDED_TEST_BINARY or BOSUN_TEST_DOWNLOAD_CORES=1")
			}
			for _, mode := range []string{"direct", "proxy-rule", "proxy-default"} {
				t.Run(mode, func(t *testing.T) { testCoreOnlyRealSingbox(t, mode, distribution, binaryPath) })
			}
		})
	}
}
func testCoreOnlyRealSingbox(t *testing.T, mode, distribution, binaryPath string) {
	var host netip.Addr
	addresses, _ := net.InterfaceAddrs()
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().Is4() && p.Addr().IsPrivate() {
			host = p.Addr()
			break
		}
	}
	if !host.IsValid() {
		t.Skip("requires a local RFC1918 interface")
	}
	echo := func(address string) net.Listener {
		l, e := net.Listen("tcp", address)
		if e != nil {
			t.Fatal("cannot create local fixture")
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(2 * time.Second))
					b := make([]byte, 4)
					if _, e := io.ReadFull(c, b); e == nil {
						c.Write(b)
					}
				}()
			}
		}()
		return l
	}
	target := echo(net.JoinHostPort(host.String(), "0"))
	port := target.Addr().(*net.TCPAddr).Port
	echo(net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) // catches mixed/rebound loopback dialing
	other := echo(net.JoinHostPort(host.String(), "0")).Addr().(*net.TCPAddr).Port
	udp, e := net.ListenPacket("udp", net.JoinHostPort(host.String(), strconv.Itoa(port)))
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		b := make([]byte, 1024)
		for {
			n, a, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			udp.WriteTo(b[:n], a)
		}
	}()
	udpAllowed, e := net.ListenPacket("udp", net.JoinHostPort(host.String(), strconv.Itoa(other)))
	if e != nil {
		t.Fatal(e)
	}
	defer udpAllowed.Close()
	go func() {
		b := make([]byte, 1024)
		for {
			n, a, e := udpAllowed.ReadFrom(b)
			if e != nil {
				return
			}
			udpAllowed.WriteTo(b[:n], a)
		}
	}()
	dns, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer dns.Close()
	var rebound atomic.Int32
	go func() {
		b := make([]byte, 4096)
		for {
			n, peer, e := dns.ReadFrom(b)
			if e != nil {
				return
			}
			var q dnsmessage.Message
			if q.Unpack(b[:n]) != nil || len(q.Questions) == 0 {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionAvailable: true}, Questions: q.Questions}
			question := q.Questions[0]
			if question.Type == dnsmessage.TypeA {
				ips := [][4]byte{host.As4()}
				name := question.Name.String()
				if strings.HasPrefix(name, "mixed.") {
					ips = append(ips, [4]byte{127, 0, 0, 1})
				}
				if strings.HasPrefix(name, "rebind.") && rebound.Add(1) > 1 {
					ips = [][4]byte{{127, 0, 0, 1}}
				}
				for _, ip := range ips {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: ip}})
				}
			}
			data, _ := reply.Pack()
			dns.WriteTo(data, peer)
		}
	}()
	freePort := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return p
	}
	inboundPort, deniedPort := freePort(), freePort()
	for deniedPort == inboundPort {
		deniedPort = freePort()
	}
	policy := &spec.PrivateAccess{Mode: "custom", Enforcement: "auto", AllowCoreOnly: true, Rules: []spec.PrivateAccessRule{{CIDR: host.String(), Protocol: "tcp", PortStart: port}, {CIDR: host.String(), Protocol: "udp", PortStart: other}}}
	n := &spec.Node{Inbounds: []spec.Inbound{{Tag: "allowed", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: inboundPort, PrivateAccess: policy}, {Tag: "denied", Protocol: spec.VLESS, Listen: "127.0.0.1", Port: deniedPort}}, DNS: []string{dns.LocalAddr().String()}}
	var proxyRequests, proxyDomains atomic.Int32
	if mode != "direct" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					c.SetDeadline(time.Now().Add(2 * time.Second))
					h := make([]byte, 2)
					if _, err := io.ReadFull(c, h); err != nil {
						return
					}
					methods := make([]byte, int(h[1]))
					if _, err := io.ReadFull(c, methods); err != nil {
						return
					}
					c.Write([]byte{5, 0})
					request := make([]byte, 4)
					if _, err := io.ReadFull(c, request); err != nil {
						return
					}
					size := 6
					if request[1] == 3 {
						switch request[3] {
						case 4:
							size = 18
						case 3:
							b := make([]byte, 1)
							if _, err := io.ReadFull(c, b); err != nil {
								return
							}
							size = int(b[0]) + 2
						}
					} else if request[3] != 1 {
						proxyDomains.Add(1)
						return
					}
					target := make([]byte, size)
					if _, err := io.ReadFull(c, target); err != nil {
						return
					}
					if request[1] == 3 { // SOCKS UDP associate: assert the datagram also carries the checked IP.
						relay, err := net.ListenPacket("udp", "127.0.0.1:0")
						if err != nil {
							return
						}
						defer relay.Close()
						rp := relay.LocalAddr().(*net.UDPAddr).Port
						c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, byte(rp >> 8), byte(rp)})
						relay.SetDeadline(time.Now().Add(time.Second))
						packet := make([]byte, 2048)
						size, peer, err := relay.ReadFrom(packet)
						if err != nil || size < 10 {
							return
						}
						proxyRequests.Add(1)
						if packet[3] != 1 {
							proxyDomains.Add(1)
							return
						}
						address := net.IP(packet[4:8]).String()
						p := int(binary.BigEndian.Uint16(packet[8:10]))
						if address != host.String() || p != other {
							return
						}
						upstream, err := net.DialTimeout("udp", net.JoinHostPort(address, strconv.Itoa(p)), time.Second)
						if err != nil {
							return
						}
						defer upstream.Close()
						upstream.SetDeadline(time.Now().Add(time.Second))
						upstream.Write(packet[10:size])
						reply := make([]byte, 2048)
						count, err := upstream.Read(reply)
						if err != nil {
							return
						}
						relay.WriteTo(append(packet[:10:10], reply[:count]...), peer)
						io.Copy(io.Discard, c)
						return
					}
					proxyRequests.Add(1)
					ip := net.IP(target[:4]).String()
					destinationPort := int(binary.BigEndian.Uint16(target[4:]))
					if ip != host.String() || destinationPort != port {
						return
					}
					upstream, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(destinationPort)), time.Second)
					if err != nil {
						return
					}
					defer upstream.Close()
					c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
					go io.Copy(upstream, c)
					io.Copy(c, upstream)
				}()
			}
		}()
		n.Outbounds = []spec.Outbound{{Tag: "proxy", Protocol: "socks", Settings: map[string]any{"server": "127.0.0.1", "server_port": listener.Addr().(*net.TCPAddr).Port, "version": "5"}}}
		n.Routes = []spec.RouteRule{{Match: []string{"port:" + strconv.Itoa(port) + "," + strconv.Itoa(other)}, Action: "outbound", Value: "proxy"}}
		if mode == "proxy-default" {
			n.DefaultOutbound = "proxy"
			n.Routes = nil
		}
	}
	users := []spec.User{{ID: 1, Name: "fixture", UUID: "11111111-1111-4111-8111-111111111111"}}
	resolved, e := n.ResolvePrivateAccessIntent(true)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := render(resolved, resolved.Inbounds, users, renderOptions{Distribution: distribution, StatsListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort()))})
	if e != nil {
		t.Fatal(e)
	}
	var config map[string]any
	json.Unmarshal(raw, &config)
	config["dns"].(map[string]any)["disable_cache"] = true
	server := config["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	server["server"] = "127.0.0.1"
	server["server_port"] = dns.LocalAddr().(*net.UDPAddr).Port
	raw, _ = json.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, binaryPath, "run", "-c", path)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cancel()
		cmd.Wait()
		if t.Failed() {
			t.Log(strings.ReplaceAll(output.String(), host.String(), "<fixture-ip>"))
		}
	}()
	ready := false
	for i := 0; i < 500; i++ {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inboundPort)), 50*time.Millisecond)
		if e == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("fixture listener startup timed out")
	}
	request := func(in int, dest string, p int, datagram bool) bool {
		c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(in)), time.Second)
		if e != nil {
			return false
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		uuid := []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x81, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11}
		h := append([]byte{0}, uuid...)
		command := byte(1)
		if datagram {
			command = 2
		}
		h = append(h, 0, command, byte(p>>8), byte(p))
		if ip, e := netip.ParseAddr(dest); e == nil {
			v := ip.As4()
			h = append(h, 1)
			h = append(h, v[:]...)
		} else {
			h = append(h, 2, byte(len(dest)))
			h = append(h, []byte(dest)...)
		}
		if datagram {
			h = append(h, 0, 4)
		}
		h = append(h, []byte("ping")...)
		if _, e = c.Write(h); e != nil {
			return false
		}
		resp := make([]byte, 2)
		if _, e = io.ReadFull(c, resp); e != nil {
			return false
		}
		if resp[1] > 0 {
			io.CopyN(io.Discard, c, int64(resp[1]))
		}
		if datagram {
			if _, e = io.ReadFull(c, resp); e != nil || binary.BigEndian.Uint16(resp) != 4 {
				return false
			}
		}
		b := make([]byte, 4)
		_, e = io.ReadFull(c, b)
		return e == nil && string(b) == "ping"
	}
	for _, tc := range []struct {
		name, dest string
		in, port   int
		udp, want  bool
	}{
		{"allowed-ip", host.String(), inboundPort, port, false, true}, {"denied-inbound", host.String(), deniedPort, port, false, false}, {"denied-port", host.String(), inboundPort, other, false, false}, {"denied-udp", host.String(), inboundPort, port, true, false}, {"allowed-udp", host.String(), inboundPort, other, true, true}, {"denied-inbound-udp", host.String(), deniedPort, other, true, false},
		{"allowed-domain", "allowed.example.com", inboundPort, port, false, true}, {"mixed-answer", "mixed.example.com", inboundPort, port, false, false}, {"rebind-first", "rebind.example.com", inboundPort, port, false, true}, {"rebind-second", "rebind.example.com", inboundPort, port, false, false}, {"loopback", "127.0.0.1", inboundPort, port, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if request(tc.in, tc.dest, tc.port, tc.udp) != tc.want {
				t.Fatal("unexpected access result")
			}
		})
	}
	if mode != "direct" && (proxyRequests.Load() != 4 || proxyDomains.Load() != 0) {
		t.Fatalf("wrong proxy delivery: requests=%d domain requests=%d", proxyRequests.Load(), proxyDomains.Load())
	}
}
