package spec

import (
	"net/url"
	"reflect"
	"testing"
)

func TestCoreCompatibilityMatrix(t *testing.T) {
	for _, tc := range []struct {
		name    string
		inbound Inbound
		want    []string
	}{
		{"ssh", Inbound{Protocol: SSH}, []string{"singbox-extended"}},
		{"vless", Inbound{Protocol: VLESS}, []string{"singbox", "xray", "singbox-extended"}},
		{"vmess", Inbound{Protocol: VMess}, []string{"singbox", "xray", "singbox-extended"}},
		{"trojan", Inbound{Protocol: Trojan}, []string{"singbox", "xray", "singbox-extended"}},
		{"ss", Inbound{Protocol: Shadowsocks, Cipher: "aes-128-gcm"}, []string{"singbox", "xray", "singbox-extended"}},
		{"ss2022", Inbound{Protocol: Shadowsocks, Cipher: "2022-blake3-aes-128-gcm"}, []string{"singbox", "singbox-extended"}},
		{"shadowtls", Inbound{Protocol: Shadowsocks, ShadowTLS: &ShadowTLS{}}, []string{"singbox", "singbox-extended"}},
		{"hy2", Inbound{Protocol: Hysteria2}, []string{"singbox", "hysteria", "singbox-extended"}},
		{"tuic", Inbound{Protocol: TUIC}, []string{"singbox", "singbox-extended"}},
		{"anytls", Inbound{Protocol: AnyTLS}, []string{"singbox", "singbox-extended"}},
		{"mieru", Inbound{Protocol: Mieru}, []string{"mita", "singbox-extended"}},
		{"snell", Inbound{Protocol: Snell}, []string{"singbox", "snell", "singbox-extended"}},
		{"snell-multi", Inbound{Protocol: Snell, SnellMultiUser: true}, []string{"singbox", "singbox-extended"}},
		{"snell-tls", Inbound{Protocol: Snell, SnellObfs: "tls"}, []string{"snell"}},
		{"socks", Inbound{Protocol: SOCKS}, []string{"singbox", "xray", "singbox-extended"}},
		{"http", Inbound{Protocol: HTTP}, []string{"singbox", "xray", "singbox-extended"}},
		{"naive", Inbound{Protocol: Naive}, []string{"singbox", "singbox-extended"}},
		{"wireguard", Inbound{Protocol: WireGuard}, []string{"xray"}},
		{"xhttp", Inbound{Protocol: VLESS, Transport: &Transport{Type: "xhttp"}}, []string{"xray"}},
		{"http2", Inbound{Protocol: VLESS, Transport: &Transport{Type: "http"}}, []string{"singbox", "singbox-extended"}},
		{"proxy", Inbound{Protocol: VLESS, AcceptProxyProtocol: true}, []string{"xray"}},
		{"fallback", Inbound{Protocol: Trojan, Fallbacks: []Fallback{{}}}, []string{"xray"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, c := range PreviewCores(tc.inbound, CoreCatalog()).Options {
				if c.Compatible {
					got = append(got, c.Name)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("compatible cores = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCorePreviewUsesRuntimePriorityAndNeverRepins(t *testing.T) {
	xray := CoreCandidate{"xray", CapabilitiesForCore("xray")}
	sb := CoreCandidate{"singbox", CapabilitiesForCore("singbox")}
	ib := Inbound{Protocol: VLESS}
	if p := PreviewCores(ib, []CoreCandidate{xray, sb}); p.AutoCore != "xray" {
		t.Fatal(p)
	}
	ib.TLS = &TLS{Mode: TLSReality}
	if p := PreviewCores(ib, []CoreCandidate{sb, xray}); p.AutoCore != "xray" {
		t.Fatal(p)
	}
	ib.Core = "singbox"
	if name, err := SelectCore(ib, []CoreCandidate{sb, xray}); err != nil || name != "singbox" {
		t.Fatalf("explicit REALITY pin: %s %v", name, err)
	}
	ib.Transport = &Transport{Type: "xhttp"}
	if name, err := SelectCore(ib, []CoreCandidate{sb, xray}); err == nil || name != "" {
		t.Fatal("must refuse an incompatible pin, not silently use xray")
	}
	if name, err := SelectCore(Inbound{Protocol: VLESS, Core: "xray"}, []CoreCandidate{sb}); err == nil || name != "" {
		t.Fatal("must refuse a disabled pin")
	}
	unknown := PreviewCores(ib, nil)
	if unknown.InventoryKnown || unknown.AutoCore != "" || unknown.Options[0].Available != nil {
		t.Fatal("old nodes must remain unknown", unknown)
	}
	empty := PreviewCores(ib, []CoreCandidate{})
	if !empty.InventoryKnown || empty.AutoCore != "" || *empty.Options[0].Available {
		t.Fatal("empty inventory must remain distinct from unknown", empty)
	}
}

func TestCoreProbeFeaturesAndExplicitValidation(t *testing.T) {
	ib := CoreProbe(url.Values{"protocol": {"shadowsocks"}, "shadow_tls": {"true"}, "cipher": {"aes-128-gcm"}, "server_key": {"must-not-be-used"}})
	if ib.ServerKey != "" || PreviewCores(ib, CoreCatalog()).AutoCore != "singbox" {
		t.Fatal(ib)
	}
	ib = Inbound{Tag: "in", Protocol: VLESS, Port: 443, Core: "singbox", Transport: &Transport{Type: "xhttp"}}
	if err := ib.Validate(); err == nil {
		t.Fatal("incompatible pin passed shared validation")
	}
	ib.Core = "xray"
	if err := ib.Validate(); err != nil {
		t.Fatal(err)
	}
}
