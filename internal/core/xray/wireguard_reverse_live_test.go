package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zeptop-dev/bosun/internal/core/grpcraw"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Exercise the pinned core's real DNS and multi-address route matcher, rather
// than assuming how IPOnDemand treats A+AAAA answers. This fixture runs only
// generated WG routes: documentation addresses would correctly be rejected by
// the normal private-address policy. No packets are dialed through the fake WG
// addresses, and no host interfaces, routes or firewall settings are changed.
func TestWireGuardDomainPreferenceLiveXray(t *testing.T) {
	binary := os.Getenv("BOSUN_XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_XRAY_TEST_BINARY to the pinned Xray executable")
	}
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var queried sync.Map
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, question := range query.Questions {
				name := question.Name.String()
				queried.Store(fmt.Sprintf("%s/%d", name, question.Type), true)
				header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 60}
				if question.Type == dnsmessage.TypeA && (name == "dual.example.com." || name == "v4.example.com.") {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AResource{A: [4]byte{198, 51, 100, 20}}})
				}
				if question.Type == dnsmessage.TypeAAAA && (name == "dual.example.com." || name == "v6.example.com.") {
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: header, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::20").As16()}})
				}
			}
			if data, err := reply.Pack(); err == nil {
				_, _ = dns.WriteTo(data, peer)
			}
		}
	}()
	t.Cleanup(func() { _ = dns.Close(); <-done })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiAddress := listener.Addr().String()
	listener.Close()
	node, users := wireGuardPreferenceFixture(t)
	rules, outbounds, err := wireGuardRoutes(&node, node.Inbounds, users)
	if err != nil {
		t.Fatal(err)
	}
	// DNS is local fixture traffic, separate from all subscriber inbounds.
	rules = append([]any{m{"type": "field", "inboundTag": []string{"fixture-dns"}, "outboundTag": "fixture-dns"}}, rules...)
	outbounds = append([]any{m{"tag": "fixture-dns", "protocol": "freedom"}}, outbounds...)
	config := m{
		"log":       m{"loglevel": "info"},
		"api":       m{"tag": "api", "listen": apiAddress, "services": []string{"RoutingService"}},
		"dns":       m{"tag": "fixture-dns", "servers": []any{m{"address": "127.0.0.1", "port": dns.LocalAddr().(*net.UDPAddr).Port}}},
		"routing":   m{"domainStrategy": "IPOnDemand", "rules": rules},
		"outbounds": outbounds,
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "routing.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, binary, "run", "-test", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("Xray rejected WG route fixture: %v: %s", err, output)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	logPath := filepath.Join(filepath.Dir(path), "xray.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	conn, err := grpc.NewClient(apiAddress, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithDefaultCallOptions(grpc.WaitForReady(true)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, ib := range node.Inbounds {
		link := node.WireGuardLinks[ib.WireGuardSlot-1]
		for _, user := range users {
			for _, target := range []string{"dual.example.com", "v4.example.com", "v6.example.com", "198.51.100.20", "2001:db8::20"} {
				v6 := target == "v6.example.com" || target == "2001:db8::20" || target == "dual.example.com" && link.DomainPreference != "ipv4"
				family := "v4"
				if v6 {
					family = "v6"
				}
				want := "wireguard-" + strconv.Itoa(link.Slot) + "-" + family
				if user.SpeedLimitMbps > 0 {
					want += "-u" + strconv.FormatInt(user.ID, 10)
				}
				callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
				response, err := grpcraw.Invoke(callCtx, conn, "/xray.app.router.command.RoutingService/TestRoute", wireGuardTestRouteRequest(ib.Tag, spec.InboundUser(user.Name, ib.Tag), target))
				callCancel()
				if err != nil {
					logs, _ := os.ReadFile(logPath)
					t.Fatalf("route %s for %s through %s: %v\n%s", target, user.Name, ib.Tag, err, logs)
				}
				if got := wireGuardTestRouteOutbound(t, response); got != want {
					t.Fatalf("preference %q user %s target %s: %s, want %s", link.DomainPreference, user.Name, target, got, want)
				}
			}
		}
	}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if _, ok := queried.Load(fmt.Sprintf("dual.example.com./%d", qtype)); !ok {
			t.Fatalf("Xray did not query the dual-stack fixture's %s record", qtype)
		}
	}
}

// The small public RoutingService wire messages are encoded with the existing
// raw-gRPC helper, without depending on an Xray module or generated stubs.
func wireGuardTestRouteRequest(inbound, user, target string) []byte {
	var route []byte
	for field, value := range map[protowire.Number]string{1: inbound, 9: user} {
		route = protowire.AppendTag(route, field, protowire.BytesType)
		route = protowire.AppendString(route, value)
	}
	for field, value := range map[protowire.Number]uint64{2: 2, 6: 443} { // TCP, destination port.
		route = protowire.AppendTag(route, field, protowire.VarintType)
		route = protowire.AppendVarint(route, value)
	}
	if address, err := netip.ParseAddr(target); err == nil {
		route = protowire.AppendTag(route, 4, protowire.BytesType)
		route = protowire.AppendBytes(route, address.AsSlice())
	} else {
		route = protowire.AppendTag(route, 7, protowire.BytesType)
		route = protowire.AppendString(route, target)
	}
	request := protowire.AppendTag(nil, 1, protowire.BytesType)
	request = protowire.AppendBytes(request, route)
	request = protowire.AppendTag(request, 2, protowire.BytesType)
	return protowire.AppendString(request, "outbound")
}

func wireGuardTestRouteOutbound(t *testing.T, data []byte) string {
	t.Helper()
	for len(data) > 0 {
		field, kind, n := protowire.ConsumeTag(data)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		data = data[n:]
		if field == 12 && kind == protowire.BytesType {
			tag, n := protowire.ConsumeString(data)
			if n < 0 {
				t.Fatal(protowire.ParseError(n))
			}
			if !strings.HasPrefix(tag, "wireguard-") {
				t.Fatalf("route escaped the managed WG outbounds: %q", tag)
			}
			return tag
		}
		n = protowire.ConsumeFieldValue(field, kind, data)
		if n < 0 {
			t.Fatal(protowire.ParseError(n))
		}
		data = data[n:]
	}
	t.Fatal("Xray returned no outbound tag")
	return ""
}
