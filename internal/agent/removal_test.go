package agent

import (
	"context"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"testing"
)

func TestRemovalLaunchIsNotCompletion(t *testing.T) {
	a := &Agent{}
	j := agentproto.Job{ID: "test", Kind: "node_remove"}
	if got := a.execJob(context.Background(), j); got.Error == "" {
		t.Fatal("unsupported installation accepted")
	}
	a.Remove = func(context.Context, agentproto.Job) error { return errors.New("unsupported paths") }
	if got := a.execJob(context.Background(), j); got.Error == "" {
		t.Fatal("launch error hidden")
	}
	a.Remove = func(context.Context, agentproto.Job) error { return nil }
	got := a.execJob(context.Background(), j)
	if got.Error != "" || string(got.Result) != `{"phase":"starting"}` {
		t.Fatalf("launch prematurely completed: %+v", got)
	}
}
