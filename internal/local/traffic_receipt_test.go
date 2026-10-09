package local

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestLocalTrafficReceiptRetryAndFailedSave(t *testing.T) {
	s := openTest(t)
	u, err := s.CreateUser(User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.PutInbound(Inbound{Inbound: spec.Inbound{Tag: "ssh", Protocol: spec.VLESS, Port: 443}, Enabled: true}, ""); err != nil {
		t.Fatal(err)
	}
	r := agentproto.Report{TrafficEpoch: "epoch", TrafficSeq: 1, Traffic: []spec.UserTraffic{{UserID: u.AccountingID(), Up: 1000}}, Inbounds: map[string]spec.Traffic{"ssh": {Up: 1000}}}
	for i := 0; i < 2; i++ {
		if _, err = s.Report(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
	s, _, err = Open(s.Path(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Report(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if s.st.Users[0].Up != 1000 || s.st.Inbounds[0].Up != 1000 {
		t.Fatal("duplicate receipt charged again")
	}
	r.TrafficSeq++
	original := s.path
	s.path = original + ".blocked"
	if err = os.Mkdir(s.path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Report(context.Background(), r); err == nil {
		t.Fatal("expected write failure")
	}
	if s.st.Users[0].Up != 1000 || s.st.TrafficSeq != 1 {
		t.Fatal("failed write mutated memory")
	}
	s.path = original
	if _, err = s.Report(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if s.st.Users[0].Up != 2000 || s.st.Inbounds[0].Up != 2000 {
		t.Fatal("retry lost or doubled counters")
	}
}
