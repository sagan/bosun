package subscription

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestSSHSubscriptionPinsHostAndNeverLeaksPrivateKey(t *testing.T) {
	ib := spec.Inbound{Tag: "ssh", Protocol: spec.SSH, Port: 2222}
	spec.FillInboundSecrets(&ib)
	l := Line{Name: "SSH", Host: "example.com", Port: 2222, Inbound: ib, UUID: "identity", Password: "password"}
	o := singboxOutbound(l)
	if o["user"] != spec.ProxyUsername(l.UUID, ib.Tag) || o["type"] != "ssh" {
		t.Fatal(o)
	}
	raw, _ := json.Marshal(o)
	if !strings.Contains(string(raw), ib.SSH.PublicKey) || strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("host key pin missing or private key exposed")
	}
	if clashProxy(l) != nil {
		t.Fatal("SSH emitted for unsupported client")
	}
	ib.Protocol = spec.Mieru
	ib.Core = "singbox-extended"
	l.Inbound = ib
	if got := clashProxy(l)["username"]; got != spec.ProxyUsername(l.UUID, ib.Tag) {
		t.Fatal(got)
	}
	ib.Core = "mita"
	l.Inbound = ib
	if got := clashProxy(l)["username"]; got != l.UUID {
		t.Fatal("existing mita credentials changed")
	}
}
