package spec

import "testing"

func TestSSHHostIdentityAndCapabilities(t *testing.T) {
	ib := Inbound{Tag: "ssh", Protocol: SSH, Port: 2222}
	FillInboundSecrets(&ib)
	if err := ib.Validate(); err != nil {
		t.Fatal(err)
	}
	key := ib.SSH.PrivateKey
	pub := ib.SSH.PublicKey
	FillInboundSecrets(&ib)
	if ib.SSH.PrivateKey != key || ib.SSH.PublicKey != pub {
		t.Fatal("host key changed on save")
	}
	if InboundTemplate(ib).SSH != nil {
		t.Fatal("host credentials leaked into preset")
	}
	ib.Core = "singbox"
	if ib.Validate() == nil {
		t.Fatal("official sing-box was offered SSH inbound")
	}
	ib.Core = "singbox-extended"
	if err := ib.Validate(); err != nil {
		t.Fatal(err)
	}
	ib.SSH.PublicKey = "wrong"
	if ib.Validate() == nil {
		t.Fatal("mismatched host pin accepted")
	}
}

func TestMieruExtendedRequiresExplicitChoiceAndWildcardListen(t *testing.T) {
	ib := Inbound{Protocol: Mieru}
	if _, err := SelectCore(ib, []CoreCandidate{{"singbox-extended", CapabilitiesForCore("singbox-extended")}}); err == nil {
		t.Fatal("auto selection changed wire credentials")
	}
	ib.Core = "singbox-extended"
	ib.Listen = "192.0.2.10"
	if CapabilitiesForCore(ib.Core).Supports(ib) {
		t.Fatal("unsupported embedded Mieru bind address accepted")
	}
	ib.Core = "mita"
	if !CapabilitiesForCore(ib.Core).Supports(ib) {
		t.Fatal("mita native listen binding rejected")
	}
}

func TestExtendedMieruIngressBinding(t *testing.T) {
	ib := Inbound{Protocol: Mieru, Core: "singbox-extended"}
	if err := ib.CheckCoreListen("10.10.0.2"); err == nil {
		t.Fatal("specific ingress bind accepted")
	}
	if err := ib.CheckCoreListen(""); err != nil {
		t.Fatal(err)
	}
	ib.Core = "mita"
	if err := ib.CheckCoreListen("10.10.0.2"); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRemoteValidation(t *testing.T) {
	host := Inbound{Protocol: SSH}
	FillInboundSecrets(&host)
	remote := Remote{Host: "example.com", Port: 2222, Username: "proxy", Password: "test-password", Settings: Inbound{Protocol: SSH}, SSH: &SSHClient{HostKey: host.SSH.PublicKey}}
	if err := remote.validateSSH(); err != nil {
		t.Fatal(err)
	}
	remote.SSH.HostKey = ""
	if err := remote.validateSSH(); err == nil {
		t.Fatal("host verification silently disabled")
	}
	remote.SSH.HostKey = host.SSH.PublicKey
	remote.SSH.PrivateKey = "/etc/ssh/ssh_host_ed25519_key"
	if err := remote.validateSSH(); err == nil {
		t.Fatal("private key file path accepted")
	}
}
