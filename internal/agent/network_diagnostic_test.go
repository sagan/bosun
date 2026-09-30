package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestNetworkDiagnosticJobExpiryAndResult(t *testing.T) {
	var a Agent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer srv.Close()
	p := spec.DiagnosticParams{DiagnosticRequest: spec.DiagnosticRequest{Type: "http", Target: srv.URL}, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	raw, _ := json.Marshal(p)
	j := agentproto.Job{ID: "check", Kind: spec.NetworkDiagnosticKind, Params: raw}
	r := a.execJob(context.Background(), j)
	var result spec.DiagnosticResult
	if json.Unmarshal(r.Result, &result) != nil || r.ID != j.ID || r.Error != "" || result.Outcome != "ok" {
		t.Fatal(r, result)
	}
	for _, expires := range []int64{0, time.Now().Add(-time.Second).Unix(), time.Now().Add(time.Hour).Unix()} {
		p.ExpiresAt = expires
		j.Params, _ = json.Marshal(p)
		if r = a.execJob(context.Background(), j); r.Error == "" || len(r.Result) != 0 {
			t.Fatal("ran stale/unbounded task", r)
		}
	}
	j.Params = json.RawMessage(`{"type":"mtr","target":"--help"}`)
	if r = a.execJob(context.Background(), j); r.Error == "" {
		t.Fatal("unvalidated task", r)
	}
}
