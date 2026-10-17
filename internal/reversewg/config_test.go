package reversewg

import (
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"github.com/zeptop-dev/bosun/pkg/wg"
)

func pair(t *testing.T) (Config, Config) {
	t.Helper()
	ak, ap, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	bk, bp, err := wg.Keypair()
	if err != nil {
		t.Fatal(err)
	}
	a := Config{Slot: 1, PrivateKey: ak, PeerKey: bp, ListenPort: 51820, MTU: 1380}
	b := Config{Slot: 1, Exit: true, PrivateKey: bk, PeerKey: ap, Endpoint: "192.0.2.1:51820", MTU: 1380}
	return a, b
}

func TestValidation(t *testing.T) {
	a, b := pair(t)
	for name, mutate := range map[string]func(*Config){
		"zero slot":             func(c *Config) { c.Slot = 0 },
		"slot overflow":         func(c *Config) { c.Slot = 16384 },
		"key injection":         func(c *Config) { c.PeerKey += "\nEndpoint = example.com:53" },
		"key newline":           func(c *Config) { c.PrivateKey += "\n" },
		"bad MTU":               func(c *Config) { c.MTU = 9000 },
		"missing receiver port": func(c *Config) { c.ListenPort = 0 },
		"receiver endpoint":     func(c *Config) { c.Endpoint = "192.0.2.1:51820" },
		"broad grant":           func(c *Config) { c.PrivateAccess = &spec.PrivateAccess{Mode: "internal"} },
		"metadata": func(c *Config) {
			c.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "100.100.100.200"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := a
			mutate(&c)
			if c.Validate() == nil {
				t.Fatal("accepted invalid configuration")
			}
		})
	}
	for _, endpoint := range []string{"example.com:53", "192.0.2.1:0", "[fe80::1%eth0]:53", "192.0.2.1:53\n"} {
		c := b
		c.Endpoint = endpoint
		if c.Validate() == nil {
			t.Fatal("accepted invalid endpoint")
		}
	}
	seen := map[string]bool{}
	for slot := 1; slot <= 16383; slot++ {
		c := a
		c.Slot = slot
		for _, exit := range []bool{false, true} {
			for _, v6 := range []bool{false, true} {
				addr := c.Address(exit, v6)
				if seen[addr] {
					t.Fatal("address collision")
				}
				seen[addr] = true
			}
		}
	}
}

func TestPeerDirectionAndSecretTransport(t *testing.T) {
	a, b := pair(t)
	for _, c := range []Config{a, b} {
		p, err := CreatePlan(c)
		if err != nil {
			t.Fatal(err)
		}
		var config string
		for _, cmd := range p {
			if strings.Contains(strings.Join(cmd.Args, " "), c.PrivateKey) {
				t.Fatal("private key in arguments")
			}
			if cmd.Name == "wg" {
				config = cmd.Stdin
			}
		}
		if c.Exit {
			if !strings.Contains(config, "PersistentKeepalive = 25") || strings.Contains(config, "0.0.0.0/0") {
				t.Fatal("exit peer policy")
			}
		} else if strings.Contains(config, "Endpoint =") || !strings.Contains(config, "AllowedIPs = 0.0.0.0/0, ::/0") {
			t.Fatal("transit peer policy")
		}
	}
}

func TestFirewallRevocationAndNoSecrets(t *testing.T) {
	a, b := pair(t)
	b.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.20.0.2/32", Protocol: "tcp", PortStart: 8080}}}
	s, err := Firewall([]Config{b})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp dport 8080-8080 ct direction original accept", "tcp sport 8080-8080 ct state established ct direction reply accept", "100.100.100.200/32 drop"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(s, b.PrivateKey) || strings.Contains(s, b.PeerKey) {
		t.Fatal("firewall contains key")
	}
	b.PrivateAccess = nil
	revoked, err := Firewall([]Config{b})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(revoked, "8080") || strings.Contains(revoked, "10.20.0.2") {
		t.Fatal("revocation retained grant")
	}
	if _, err := Firewall([]Config{a, a}); err == nil {
		t.Fatal("duplicate slot accepted")
	}
}

func TestPMTUUsesOriginalGrantAndOnlyRelatedErrors(t *testing.T) {
	a, b := pair(t)
	a.PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.20.0.0/24", Protocol: "udp", PortStart: 18080}}}
	b.PrivateAccess = a.PrivateAccess
	for _, c := range []Config{a, b} {
		rules, err := Firewall([]Config{c})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"icmp type destination-unreachable icmp code frag-needed ct state related ct direction reply",
			"icmpv6 type packet-too-big ct state related ct direction reply",
			"ct original ip saddr 10.10.0.5 jump pmtu_1_ip",
			"ct original ip daddr 10.20.0.0/24 ct original protocol udp ct original proto-dst 18080-18080 counter accept",
		} {
			if !strings.Contains(rules, want) {
				t.Fatalf("missing %q", want)
			}
		}
		if strings.Contains(rules, "ct state related accept") {
			t.Fatal("blanket related bypass")
		}
		c.PrivateAccess = nil
		revoked, err := Firewall([]Config{c})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(revoked, "ct original proto-dst 18080") {
			t.Fatal("revoked ICMP permission retained")
		}
	}
}
