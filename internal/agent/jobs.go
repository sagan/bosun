package agent

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zeptop-dev/bosun/internal/netdiag"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/internal/realityscan"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// runJobs starts every job in the panel's state that has not run yet. Each
// runs in its own goroutine; its result is queued for the next report and
// an out-of-band report is requested so the panel sees it within seconds.
func (a *Agent) runJobs(ctx context.Context) {
	src, ok := a.driver.(panel.JobSource)
	if !ok {
		return
	}
	jobs := src.Jobs()
	current := map[string]bool{}
	for _, j := range jobs {
		current[j.ID] = true
	}
	a.jobsMu.Lock()
	// Forget finished jobs the panel already dropped so the set stays small.
	for id := range a.jobsDone {
		if !current[id] {
			delete(a.jobsDone, id)
		}
	}
	var start []agentproto.Job
	for _, j := range jobs {
		if a.jobsDone[j.ID] || a.jobsRunning[j.ID] {
			continue
		}
		a.jobsRunning[j.ID] = true
		start = append(start, j)
	}
	a.jobsMu.Unlock()
	for _, j := range start {
		go func(j agentproto.Job) {
			a.log.Info("job started", "id", j.ID, "kind", j.Kind)
			res := a.execJob(ctx, j)
			a.jobsMu.Lock()
			delete(a.jobsRunning, j.ID)
			a.jobsDone[j.ID] = true
			a.jobResults = append(a.jobResults, res)
			a.jobsMu.Unlock()
			a.log.Info("job finished", "id", j.ID, "kind", j.Kind, "error", res.Error)
			select {
			case a.reportNow <- struct{}{}:
			default:
			}
		}(j)
	}
}

func (a *Agent) execJob(ctx context.Context, j agentproto.Job) agentproto.JobResult {
	out := agentproto.JobResult{ID: j.ID, Kind: j.Kind}
	switch j.Kind {
	case spec.NetworkDiagnosticKind:
		var p spec.DiagnosticParams
		if err := json.Unmarshal(j.Params, &p); err != nil || p.Validate() != nil {
			out.Error = "invalid diagnostic request"
			break
		}
		now := time.Now().Unix()
		if p.ExpiresAt <= now || p.ExpiresAt > now+spec.DiagnosticTTLSeconds+30 {
			out.Error = "diagnostic request expired or clock is out of sync"
			break
		}
		jctx, cancel := context.WithDeadline(ctx, time.Unix(p.ExpiresAt, 0))
		defer cancel()
		out.Result, _ = json.Marshal(netdiag.Default.Run(jctx, p.DiagnosticRequest))
	case "reality_scan":
		var p struct {
			Hosts []string `json:"hosts"`
			Port  int      `json:"port"`
		}
		_ = json.Unmarshal(j.Params, &p)
		jctx, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		res := realityscan.Scan(jctx, p.Hosts, realityscan.Options{Port: p.Port})
		out.Result, _ = json.Marshal(res)
	case "warp_register":
		r := a.warpRegisterJob(ctx, j.Params)
		out.Result, out.Error = r.Result, r.Error
	case "node_remove":
		if a.Remove == nil {
			out.Error = "remote removal is unavailable on this installation"
			break
		}
		if err := a.Remove(ctx, j); err != nil {
			out.Error = err.Error()
			break
		}
		out.Result = json.RawMessage(`{"phase":"starting"}`)
	case "rollback":
		if a.Rollback == nil {
			out.Error = "self-update is disabled on this node"
			break
		}
		ver, err := a.Rollback()
		if err != nil {
			out.Error = err.Error()
			break
		}
		out.Result, _ = json.Marshal(map[string]string{"version": ver})
		a.log.Warn("rolled back on panel request; restarting", "to", ver)
		// The result rides on the out-of-band report runJobs asks for;
		// give it a moment before the process exits for the supervisor.
		selfupdate.Restart(5 * time.Second)
	default:
		out.Error = "unknown job kind " + j.Kind
	}
	return out
}

// takeJobResults hands the queued results to a report.
func (a *Agent) takeJobResults() []agentproto.JobResult {
	a.jobsMu.Lock()
	defer a.jobsMu.Unlock()
	out := a.jobResults
	a.jobResults = nil
	return out
}

// requeueJobResults puts results back after a failed report.
func (a *Agent) requeueJobResults(rs []agentproto.JobResult) {
	if len(rs) == 0 {
		return
	}
	a.jobsMu.Lock()
	a.jobResults = append(rs, a.jobResults...)
	a.jobsMu.Unlock()
}
