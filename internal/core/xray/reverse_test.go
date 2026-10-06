package xray

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestReverseRender(t *testing.T) {
	u := spec.Inbound{Tag: "customer", Protocol: spec.VLESS, Port: 18445, Core: "xray", Reverse: &spec.ReverseInbound{ID: "one"}}
	c := spec.Inbound{Tag: "control", Protocol: spec.VLESS, Port: 38921, Core: "xray", Reverse: &spec.ReverseInbound{ID: "one", Receiver: true, UUID: "00000000-0000-4000-8000-000000000002"}}
	n := spec.Node{PrivateDestAllow: []string{"10.10.0.2/32"}, Routes: []spec.RouteRule{{Match: []string{"network:tcp"}, Action: "direct"}}}
	b, st, err := render(&n, []spec.Inbound{u, c}, []spec.User{{Name: "paid", UUID: "00000000-0000-4000-8000-000000000001", ID: 1, SpeedLimitMbps: 10}}, renderOptions{APIListen: "127.0.0.1:9102"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	if rules[1].(map[string]any)["outboundTag"] != "reverse-one" {
		t.Fatal("managed exit shadowed by direct/private/shaping rules")
	}
	if _, ok := st.users["control"]; ok {
		t.Fatal("tunnel identity entered customer hot reload")
	}
	ins := cfg["inbounds"].([]any)
	clients := ins[1].(map[string]any)["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["reverse"] == nil {
		t.Fatal("receiver must only accept reverse identity")
	}
	n = spec.Node{ReverseClients: []spec.ReverseClient{{ID: "one", Host: "198.51.100.20", Port: 38921, UUID: c.Reverse.UUID}}}
	b, _, err = render(&n, nil, nil, renderOptions{APIListen: "127.0.0.1:9102"})
	if err != nil {
		t.Fatal("reverse-only exit failed", err)
	}
	if !strings.Contains(string(b), `"reverse"`) {
		t.Fatal("missing active client")
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	rules = cfg["routing"].(map[string]any)["rules"].([]any)
	blocked := false
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["outboundTag"] == "block" {
			blocked = true
		}
		if rule["outboundTag"] == "direct" && !blocked {
			t.Fatal("exit routed direct before private-address block")
		}
	}
	for _, patch := range []string{`{"routing":null}`, `{"outbounds":[]}`, `{"policy":{}}`} {
		n.Overrides = map[string]json.RawMessage{"xray": json.RawMessage(patch)}
		if _, _, err := render(&n, nil, nil, renderOptions{}); err == nil {
			t.Fatal("managed override accepted", patch)
		}
	}
}

// Real pinned Xray: two transit receivers and one reverse-only exit. This
// checks wire behavior, authenticated reverse registration, per-user accounting
// and fail-closed operation before the first connection and after disconnection.
// Targets are local fixtures; no external service is contacted. The receiver
// uses a local non-127.0.0.1 address because Xray omits that IP from online maps.
func TestReverseLiveXray(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testReverseLiveXray(t, false) })
	t.Run("REALITY", func(t *testing.T) { testReverseLiveXray(t, true) })
}
func testReverseLiveXray(t *testing.T, reality bool) {
	binary := os.Getenv("BOSUN_XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set BOSUN_XRAY_TEST_BINARY to the pinned Xray executable")
	}
	ctx := context.Background()
	receiverHost := "127.0.0.2"
	probe, probeErr := net.Listen("tcp", receiverHost+":0")
	if probeErr == nil {
		probe.Close()
	} else {
		receiverHost = ""
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip, _, err := net.ParseCIDR(addr.String())
				if err == nil && ip.To4() != nil && ip.IsPrivate() {
					receiverHost = ip.String()
					break
				}
			}
			if receiverHost != "" {
				break
			}
		}
		if receiverHost == "" {
			t.Skip("need a local receiver address other than 127.0.0.1 for Xray online counters")
		}
	}
	free := func() int {
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return p
	}
	makeCore := func() *Core {
		c, e := New(Options{Binary: binary, WorkDir: t.TempDir(), APIListen: net.JoinHostPort("127.0.0.1", strconv.Itoa(free())), LogLevel: "warning"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _ = c.Stop(ctx) })
		return c
	}
	start := func(c *Core, n spec.Node, ibs []spec.Inbound, us []spec.User) {
		b, e := c.Render(&n, ibs, us)
		// Linux can use another loopback source; Xray deliberately ignores
		// 127.0.0.1 in its online counters.
		if e == nil && receiverHost == "127.0.0.2" && len(n.ReverseClients) > 0 {
			var cfg map[string]any
			_ = json.Unmarshal(b.Files[b.Main], &cfg)
			for _, o := range cfg["outbounds"].([]any) {
				m := o.(map[string]any)
				if m["protocol"] == "vless" {
					m["sendThrough"] = receiverHost
				}
			}
			b.Files[b.Main], _ = json.Marshal(cfg)
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = c.Start(ctx, b); e != nil {
			t.Fatal(e)
		}
	}
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "reverse-ok") }))
	defer server.Close()
	_, ps, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	targetPort, _ := strconv.Atoi(ps)
	u := spec.User{ID: 1, Name: "paid", UUID: "00000000-0000-4000-8000-000000000001"}
	realityTarget := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	realityTarget.Config.ErrorLog = log.New(io.Discard, "", 0)
	realityTarget.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519}}
	realityTarget.StartTLS()
	defer realityTarget.Close()
	_, rp, _ := net.SplitHostPort(strings.TrimPrefix(realityTarget.URL, "https://"))
	realityPort, _ := strconv.Atoi(rp)
	var as []*Core
	var userPorts, controlPorts []int
	var clients []spec.ReverseClient
	directPort := free()
	for i := range 2 {
		id := fmt.Sprint(i + 1)
		controlUUID := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+2)
		up, cp := free(), free()
		ibs := []spec.Inbound{{Tag: "user", Core: "xray", NoSniff: true, Protocol: spec.VLESS, Listen: "127.0.0.1", Port: up, Reverse: &spec.ReverseInbound{ID: id}}, {Tag: "control", Core: "xray", NoSniff: true, Protocol: spec.VLESS, Listen: receiverHost, Port: cp, Reverse: &spec.ReverseInbound{ID: id, Receiver: true, UUID: controlUUID}}}
		if reality {
			ibs[1].TLS = &spec.TLS{Mode: spec.TLSReality, ServerName: "example.com", Reality: &spec.Reality{HandshakeServer: "127.0.0.1", HandshakePort: realityPort}}
			spec.FillInboundSecrets(&ibs[1])
		}
		var clientTLS *spec.TLS
		if reality {
			cp := *ibs[1].TLS
			rp := *cp.Reality
			rp.PrivateKey = ""
			cp.Reality = &rp
			clientTLS = &cp
		}
		if i == 0 {
			ibs = append(ibs, spec.Inbound{Tag: "ordinary", Core: "xray", NoSniff: true, Protocol: spec.VLESS, Listen: "127.0.0.1", Port: directPort})
		}
		c := makeCore()
		start(c, spec.Node{AllowPrivateDest: true}, ibs, []spec.User{u})
		as = append(as, c)
		userPorts = append(userPorts, up)
		controlPorts = append(controlPorts, cp)
		clients = append(clients, spec.ReverseClient{ID: id, Host: receiverHost, Port: cp, UUID: controlUUID, TLS: clientTLS})
	}
	request := func(port int, uuid string) (string, error) {
		host := "127.0.0.1"
		for _, cp := range controlPorts {
			if cp == port {
				host = receiverHost
			}
		}
		conn, e := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), time.Second)
		if e != nil {
			return "", e
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		id, _ := hex.DecodeString(strings.ReplaceAll(uuid, "-", ""))
		header := append([]byte{0}, id...)
		header = append(header, 0, 1, byte(targetPort>>8), byte(targetPort), 1, 127, 0, 0, 1)
		if _, e = conn.Write(append(header, []byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")...)); e != nil {
			return "", e
		}
		var response [2]byte
		if _, e = io.ReadFull(conn, response[:]); e != nil {
			return "", e
		}
		if _, e = io.CopyN(io.Discard, conn, int64(response[1])); e != nil {
			return "", e
		}
		r, e := http.ReadResponse(bufio.NewReader(conn), nil)
		if e != nil {
			return "", e
		}
		defer r.Body.Close()
		body, e := io.ReadAll(r.Body)
		return string(body), e
	}
	if _, e := request(userPorts[0], u.UUID); e == nil || hits.Load() != 0 {
		t.Fatal("unconnected reverse fell back to transit egress")
	}
	if b, e := request(directPort, u.UUID); e != nil || b != "reverse-ok" {
		t.Fatal("ordinary inbound broken", e)
	}
	before := hits.Load()
	for i := range 2 {
		if _, e := request(controlPorts[i], clients[i].UUID); e == nil {
			t.Fatal("tunnel identity accepted ordinary proxy request")
		}
	}
	if hits.Load() != before {
		t.Fatal("tunnel auth bypass")
	}
	b := makeCore()
	start(b, spec.Node{AllowPrivateDest: true, ReverseClients: clients}, nil, nil)
	deadline := time.Now().Add(15 * time.Second)
	for {
		all := true
		for i, a := range as {
			v := a.ReverseStatus(ctx)[clients[i].ID]
			all = all && v != nil && *v
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			for i, a := range as {
				sample, err := a.sample(ctx)
				t.Logf("sample A%d: %v, err %v, running %v", i, sample, err, a.Running())
				body, err := request(userPorts[i], u.UUID)
				t.Logf("data A%d: %q err %v", i, body, err)
			}
			t.Fatal("reverse clients did not connect")
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i, p := range userPorts {
		if got, e := request(p, u.UUID); e != nil || got != "reverse-ok" {
			t.Fatalf("transit %d request failed: %v", i, e)
		}
	}
	for _, a := range as {
		stats, e := a.Stats(ctx, false)
		if e != nil {
			t.Fatal(e)
		}
		if stats["paid|user"].Up+stats["paid|user"].Down == 0 {
			t.Fatal("user traffic not counted at transit")
		}
		for key := range stats {
			if spec.IsReverseEmail(key) {
				t.Fatal("tunnel traffic counted as customer")
			}
		}
	}
	if e := b.Stop(ctx); e != nil {
		t.Fatal(e)
	}
	before = hits.Load()
	for _, p := range userPorts {
		if _, e := request(p, u.UUID); e == nil {
			t.Fatal("disconnected reverse fell back to A")
		}
	}
	if hits.Load() != before {
		t.Fatal("disconnect reached destination")
	}
	if got, e := request(directPort, u.UUID); e != nil || got != "reverse-ok" {
		t.Fatal("direct inbound affected by exit disconnect", e)
	}
}
