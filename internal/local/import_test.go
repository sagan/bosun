package local

import (
	"context"
	"log/slog"
	"reflect"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestImportManagedPreservesScopesAndPolicies(t *testing.T) {
	s := openTest(t)
	alice := spec.User{ID: 71, Name: "11111111-1111-4111-8111-111111111111", UUID: "11111111-1111-4111-8111-111111111111", Password: "password-example", SpeedLimitMbps: 3, DeviceLimit: 2, QuotaBytes: 1024, QuotaDays: 30}
	aliceVIP := alice
	aliceVIP.SpeedLimitMbps = 8
	aliceVIP.QuotaBytes = 4096
	excluded := spec.User{ID: 72, UUID: "22222222-2222-4222-8222-222222222222"}
	st := &agentproto.State{Node: spec.Node{Inbounds: []spec.Inbound{
		{Tag: "a", Protocol: spec.VLESS, Port: 9443, ScopedUsers: true, Users: []spec.User{alice}},
		{Tag: "b", Protocol: spec.VLESS, Port: 9444, ScopedUsers: true, Users: []spec.User{aliceVIP}},
		{Tag: "empty", Protocol: spec.VLESS, Port: 9445, ScopedUsers: true},
	}, DNS: []string{"192.0.2.10"}, PrivateDestAllow: []string{"10.10.0.2/32"}, EgressByIngress: true, ACME: &spec.ACME{Email: "admin@example.com"}, Decoy: &spec.Decoy{Domain: "decoy.example.com", Port: 8443}, DefaultOutbound: "direct"}, Users: []spec.User{alice, excluded}, Forwards: []spec.Forward{{Tag: "relay", Port: 9805, Target: "198.51.100.20:443"}}}
	if err := s.ImportManaged(st); err != nil {
		t.Fatal(err)
	}
	// Reload the file, so all guarantees also hold across a service restart.
	s, _, err := Open(s.path, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	node, _, err := s.Node(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Inbounds) != 3 || len(node.Forwards) != 1 || !node.EgressByIngress || !reflect.DeepEqual(node.PrivateDestAllow, st.Node.PrivateDestAllow) || !reflect.DeepEqual(node.DNS, st.Node.DNS) || node.Decoy.Port != 8443 || node.ACME.Email != "admin@example.com" {
		t.Fatalf("lost node policies: %+v", node)
	}
	for i, want := range []spec.User{alice, aliceVIP} {
		ib := node.Inbounds[i]
		if !ib.ScopedUsers || len(ib.Users) != 1 || !reflect.DeepEqual(ib.Users[0], want) {
			t.Fatalf("lost scope/credential/limit: %+v", ib)
		}
	}
	if !node.Inbounds[2].ScopedUsers || len(node.Inbounds[2].Users) != 0 {
		t.Fatal("empty scope became unrestricted")
	}
	users := s.ListUsers()
	if len(users) != 2 || users[1].Enabled {
		t.Fatal("excluded account became active")
	}
	if users[0].ID != 1 || users[0].TrafficID != 71 || users[0].SubToken == "" {
		t.Fatal("local identity/traffic identity invalid")
	}
	if err := s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "new", Protocol: spec.VLESS, Port: 9446}, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	node, _, _ = s.Node(context.Background())
	if !node.Inbounds[3].ScopedUsers || len(node.Inbounds[3].Users) != 0 {
		t.Fatal("new inbound leaked access")
	}
	u := users[0]
	u.SpeedLimitMbps = 10
	if err := s.UpdateUser(u); err != nil {
		t.Fatal(err)
	}
	node, _, _ = s.Node(context.Background())
	if node.Inbounds[0].Users[0].SpeedLimitMbps != 10 {
		t.Fatal("local edit did not replace imported limits")
	}
}
