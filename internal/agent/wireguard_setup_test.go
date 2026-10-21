package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestWireGuardSetupRejectsInvalidJobs(t *testing.T) {
	a := &Agent{}
	for _, p := range []spec.WireGuardSetupRequest{{Action: "shell", ExpiresAt: time.Now().Unix() + 60}, {Action: "install", ExpiresAt: time.Now().Unix() - 1}, {Action: "install", ExpiresAt: time.Now().Unix() + 10000}} {
		raw, _ := json.Marshal(p)
		res := a.execJob(context.Background(), agentproto.Job{ID: "test", Kind: spec.WireGuardSetupKind, Params: raw})
		if res.Error == "" {
			t.Fatal("accepted unsafe job", p)
		}
	}
	raw, _ := json.Marshal(spec.WireGuardSetupRequest{Action: "check", ExpiresAt: time.Now().Unix() + 60})
	res := a.execJob(context.Background(), agentproto.Job{ID: "test", Kind: spec.WireGuardSetupKind, Params: raw})
	var got spec.WireGuardSetupResult
	if res.Error != "" || json.Unmarshal(res.Result, &got) != nil || got.Status == nil || len(got.Status.Checks) == 0 {
		t.Fatal(res)
	}
}
