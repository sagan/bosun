package agent

import (
	"context"
	"errors"
	"log/slog"
	"os/user"
	"strings"
	"testing"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type privateFeatureCore struct{ *fakeCore }

func (f *privateFeatureCore) Capabilities() core.Capabilities {
	return spec.CapabilitiesForCore(f.name)
}

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
	reg.Register(&privateFeatureCore{c})
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
	// Adapter features remain independent of guard state; the legacy runtime
	// availability flag continues to fail closed.
	before := a.CoreCandidates()[0].Capabilities
	a.EgressDisabled = true
	after := a.CoreCandidates()[0].Capabilities
	if before.PrivateAccessPolicy == nil || after.PrivateAccessPolicy == nil || *before.PrivateAccessPolicy != *after.PrivateAccessPolicy {
		t.Fatal("guard state changed adapter features")
	}
	if after.PrivateAccessReadiness.EffectiveMode != "core_only" || before.PrivateAccessReadiness.EffectiveMode != "dual" {
		t.Fatal("runtime mode did not track actual guard state")
	}
	if after.PrivateAccess {
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

func TestCoreOnlyExplicitGateAndRevocation(t *testing.T) {
	account, e := user.Current()
	if e != nil {
		t.Fatal(e)
	}
	if account.Uid == "0" {
		account, e = user.LookupId("65534")
		if e != nil {
			t.Skip("no fixture account")
		}
	}
	if e = runas.Set(account.Username); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(runas.Clear)
	c := &fakeCore{name: "singbox", protos: []spec.Protocol{spec.VLESS}, running: true}
	reg := core.NewRegistry()
	reg.Register(c)
	a := &Agent{reg: reg, log: slog.Default(), driver: nopDriver{}, EgressDisabled: true}
	a.Egress = &egressguard.Guard{Run: func(_ context.Context, script, _ string, _ ...string) ([]byte, error) {
		if strings.Contains(script, "meta mark") {
			t.Fatal("core-only emitted nft grant")
		}
		return nil, nil
	}}
	policy := &spec.PrivateAccess{Mode: "internal", Enforcement: "core_only"}
	n := &spec.Node{Inbounds: []spec.Inbound{{Tag: "private", Protocol: spec.VLESS, PrivateAccess: policy}}}
	if !a.coreOnlyPrivateAccessReady() || a.privateAccessReady() {
		t.Fatal("mode gate wrong")
	}
	if e = a.preparePrivateAccess(context.Background(), n, nil); e != nil {
		t.Fatal(e)
	}
	if c.running {
		t.Fatal("old sockets survived policy change")
	}
	c.running = true
	if e = a.preparePrivateAccess(context.Background(), n, nil); e != nil || !c.running {
		t.Fatal("stable policy restarted core", e)
	}
	policy.Mode = "off"
	policy.Enforcement = ""
	if e = a.preparePrivateAccess(context.Background(), n, nil); e != nil || c.running {
		t.Fatal("revocation failed", e)
	}
	a.EgressDisabled = false
	if a.coreOnlyPrivateAccessReady() {
		t.Fatal("core-only ignored system guard")
	}
}
