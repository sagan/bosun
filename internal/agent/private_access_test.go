package agent

import (
	"context"
	"errors"
	"log/slog"
	"os/user"
	"testing"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestPrivateAccessApplyFailClosedAndRevocation(t *testing.T) {
	account, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	if account.Uid == "0" {
		account, e = user.LookupId("65534")
		if e != nil {
			t.Skip("no non-root account")
		}
	}
	if err := runas.Set(account.Username); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runas.Clear)
	c := &fakeCore{name: "xray", protos: []spec.Protocol{spec.VLESS}, running: true}
	reg := core.NewRegistry()
	reg.Register(c)
	fail := false
	applies := 0
	a := &Agent{reg: reg, log: slog.Default(), users: []spec.User{{ID: 1, Name: "u"}}, driver: nopDriver{}}
	a.Egress = &egressguard.Guard{Run: func(context.Context, string, string, ...string) ([]byte, error) {
		applies++
		if fail {
			return nil, errors.New("nft unavailable")
		}
		if c.running {
			t.Fatal("policy installed before old core stopped")
		}
		return nil, nil
	}}
	n := &spec.Node{Inbounds: []spec.Inbound{{Tag: "allowed", Protocol: spec.VLESS, PrivateAccess: &spec.PrivateAccess{Mode: "internal"}}}}
	if err := a.preparePrivateAccess(context.Background(), n, nil); err != nil {
		t.Fatal(err)
	}
	if c.running || applies == 0 || !a.privatePolicyActive {
		t.Fatal("did not enforce before start")
	}
	c.running = true
	if err := a.preparePrivateAccess(context.Background(), n, nil); err != nil || !c.running {
		t.Fatal("unchanged policy disconnected users", err)
	}
	n.Inbounds[0].PrivateAccess = &spec.PrivateAccess{Mode: "custom", Rules: []spec.PrivateAccessRule{{CIDR: "10.10.0.2"}}}
	fail = true
	if err := a.preparePrivateAccess(context.Background(), n, nil); err == nil || c.running {
		t.Fatal("guard failure did not close old core")
	}
	fail = false
	if err := a.preparePrivateAccess(context.Background(), n, nil); err != nil {
		t.Fatal(err)
	}
	c.running = true
	n.Inbounds[0].PrivateAccess = &spec.PrivateAccess{Mode: "off"}
	if err := a.preparePrivateAccess(context.Background(), n, nil); err != nil || c.running || a.privatePolicyActive {
		t.Fatal("revoke failed", err)
	}
	// Root/disabled/broad bypass must never advertise enforcement.
	a.EgressDisabled = true
	if a.CoreCandidates()[0].Capabilities.PrivateAccess {
		t.Fatal("disabled guard advertised")
	}
}

func TestPrivateAccessAdditionalMarksShareUserLimit(t *testing.T) {
	n := &spec.Node{UserSpeedLimitMbps: 2, Inbounds: []spec.Inbound{{Tag: "a", PrivateAccess: &spec.PrivateAccess{Mode: "internal"}}, {Tag: "b", PrivateAccess: &spec.PrivateAccess{Mode: "internal"}}}}
	grants, err := n.PrivateGrants([]spec.User{{ID: 123, Name: "u"}})
	if err != nil {
		t.Fatal(err)
	}
	limit := shaper.Limit{UserID: 123, Mbps: 2}
	for _, g := range grants {
		if g.UserID == limit.UserID {
			limit.Marks = append(limit.Marks, g.Mark)
		}
	}
	if len(limit.Marks) != 2 || limit.Marks[0] == limit.Marks[1] {
		t.Fatal("user/inbound scopes collapsed", limit)
	}
}

func TestPrivateAccessRestartClearsOldGrantsBeforeCoreStart(t *testing.T) {
	c := &fakeCore{name: "xray", protos: []spec.Protocol{spec.VLESS}}
	reg := core.NewRegistry()
	reg.Register(c)
	touched := false
	a := &Agent{reg: reg, log: slog.Default()}
	a.Egress = &egressguard.Guard{Run: func(context.Context, string, string, ...string) ([]byte, error) {
		touched = true
		if c.running {
			t.Fatal("started core before stale grant reconciliation")
		}
		return nil, nil
	}}
	if err := a.preparePrivateAccess(context.Background(), &spec.Node{}, nil); err != nil {
		t.Fatal(err)
	}
	if !touched {
		t.Fatal("empty first policy left old grants installed")
	}
}
