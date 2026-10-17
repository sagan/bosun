package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) MonitorOnly() bool { return a.cfg != nil && a.cfg.NodeMode == spec.NodeMonitor }

func (a *Agent) modeIdentity() string {
	if d, ok := a.driver.(interface{ TrafficIdentity() string }); ok {
		return d.TrafficIdentity()
	}
	return ""
}

func (a *Agent) modeRevision() uint64 {
	if a.cfg == nil || a.cfg.NodeModeIdentity != a.modeIdentity() {
		return 0
	}
	return a.cfg.NodeModeRevision
}

// Proxy side effects must wait for the process running the desired mode
// generation. In particular, a failed or stale apply cannot still install
// forwarding rules through the independently reconciled forward path.
func (a *Agent) proxyModeReady(node *spec.Node) bool {
	return node != nil && !a.MonitorOnly() && !a.modeChanging.Load() &&
		node.Mode.Effective() == spec.NodeFull && node.ModeRevision == a.modeRevision()
}

// Mode changes are serialized with apply and core activation. Persist only
// after old processes and owned network helpers have been stopped/cleared.
func (a *Agent) applyNodeMode(ctx context.Context) (bool, error) {
	if err := a.node.Mode.Validate(); err != nil {
		return true, err
	}
	if a.modeChanging.Load() {
		return true, nil
	}
	if a.node.ModeRevision < a.modeRevision() {
		return true, errors.New("stale node mode revision")
	}
	target := a.node.Mode
	if target == "" {
		target = a.cfg.NodeMode.Effective()
	}
	if target != a.cfg.NodeMode.Effective() && a.node.ModeRevision <= a.modeRevision() {
		return true, errors.New("mode change requires a newer revision")
	}
	if target == a.cfg.NodeMode.Effective() && a.node.ModeRevision == a.modeRevision() {
		if !a.MonitorOnly() {
			return false, nil
		}
		return true, spec.ValidateMonitorState(a.node, a.users, a.cfg.ForwardSpecs())
	}
	if err := spec.ValidateMonitorState(a.node, a.users, a.cfg.ForwardSpecs()); err != nil {
		return true, err
	}
	if a.ChangeMode == nil {
		return true, errors.New("node mode switching is unavailable on this installation")
	}
	if a.CoreManager != nil {
		if !a.CoreManager.TryLock() {
			return true, errors.New("wait for the core operation to finish before changing node mode")
		}
		defer a.CoreManager.Unlock()
	}
	a.jobsMu.Lock()
	for _, running := range a.jobsRunning {
		if running {
			a.jobsMu.Unlock()
			return true, errors.New("wait for running node jobs before changing node mode")
		}
	}
	a.modeChanging.Store(true)
	a.jobsMu.Unlock()
	success := false
	defer func() {
		if !success {
			a.modeChanging.Store(false)
		}
	}()
	if err := a.checkpointTraffic(ctx); err != nil {
		return true, err
	}
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if c.Running() {
			if err := c.Stop(ctx); err != nil {
				return true, fmt.Errorf("stop core before mode change: %w", err)
			}
		}
	}
	if err := a.clearWireGuard(ctx); err != nil {
		return true, err
	}
	if err := a.fwd.Apply(nil); err != nil {
		return true, err
	}
	if a.Decoy != nil {
		a.Decoy.Configure(ctx, nil)
	}
	if !a.MonitorOnly() {
		if a.Shaper != nil {
			if err := a.Shaper.Apply(ctx, nil); err != nil {
				return true, err
			}
		}
		if a.Guard != nil {
			if err := a.Guard.Apply(ctx, nil); err != nil {
				return true, err
			}
		}
		if a.Egress != nil {
			if err := a.Egress.Apply(ctx, -1, egressguard.Options{Disabled: true}); err != nil {
				return true, err
			}
		}
		if a.Firewall != nil {
			if err := a.Firewall.Apply(ctx, a.ExtraPorts); err != nil {
				return true, err
			}
		}
	}
	if err := a.ChangeMode(target, a.node.ModeRevision, a.modeIdentity()); err != nil {
		return true, err
	}
	success = true
	return true, nil
}
