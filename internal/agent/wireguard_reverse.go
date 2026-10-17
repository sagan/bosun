package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/zeptop-dev/bosun/internal/reversewg"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Owned by the serial apply loop. The atomic activity flag is the only part
// read by the asynchronous doctor; it must not repair the legacy shaper while
// its IFB is being used by the aggregate controller.
type wireGuardRuntime struct {
	transport *reversewg.Manager
	shaping   *shaper.Shared
	ready     func() bool
}

func hasWireGuard(n *spec.Node) bool {
	if n == nil {
		return false
	}
	if len(n.WireGuardLinks) > 0 {
		return true
	}
	for _, ib := range n.Inbounds {
		if ib.WireGuardSlot != 0 {
			return true
		}
	}
	return false
}

func (a *Agent) initWireGuard() {
	if a.wireGuard != nil || a.cfg == nil || a.cfg.DataDir == "" {
		return
	}
	dir := filepath.Join(a.cfg.DataDir, "reversewg")
	a.wireGuard = &wireGuardRuntime{
		transport: &reversewg.Manager{Dir: dir, Backend: &reversewg.Linux{}},
		shaping:   &shaper.Shared{Dir: dir, Legacy: a.Shaper},
	}
}

func (a *Agent) wireGuardReady() bool {
	return !a.MonitorOnly() && a.privateAccessReady() && a.Shaper != nil && a.Shaper.Supported() && (&reversewg.Linux{}).Supported()
}

func (a *Agent) prepareWireGuard(ctx context.Context) error {
	a.initWireGuard()
	active := hasWireGuard(a.node)
	if !active && a.wireGuard == nil {
		return nil
	}
	if active {
		a.wireGuardActive.Store(true)
		if err := a.node.ValidateWireGuardLinks(); err != nil {
			return err
		}
		ready := a.wireGuardReady()
		if a.wireGuard != nil && a.wireGuard.ready != nil {
			ready = a.wireGuard.ready()
		}
		if !ready {
			return fmt.Errorf("reverse WireGuard requires Linux root, ip/wg/nft/tc, non-root cores and enabled egress protection")
		}
		if a.wireGuard == nil {
			return fmt.Errorf("reverse WireGuard requires a persistent data directory")
		}
	}
	if a.wireGuard == nil {
		return nil
	}
	_, err := a.wireGuard.transport.Reconcile(ctx, a.node.WireGuardLinks, a.stopPrivateCores)
	if err != nil {
		return err
	}
	// Retire aggregate IFBs before ordinary private-access shaping can create
	// its replacement. Otherwise cleanup would delete the new download IFB.
	if !hasWireGuardTransit(a.node) {
		if err := a.wireGuard.shaping.Reconcile(ctx, nil, nil, a.stopPrivateCores); err != nil {
			return err
		}
	}
	return nil
}

// Called before bootstrap (which may wait for Captain), during mode changes
// and shutdown. Never leave a previous B forwarding on an obsolete grant.
func (a *Agent) clearWireGuard(ctx context.Context) error {
	a.initWireGuard()
	if a.wireGuard == nil {
		return nil
	}
	_, err := a.wireGuard.transport.Reconcile(ctx, nil, a.stopPrivateCores)
	if err != nil {
		return err
	}
	if err := a.wireGuard.shaping.Reconcile(ctx, nil, nil, a.stopPrivateCores); err != nil {
		return err
	}
	a.wireGuardActive.Store(false)
	return nil
}

func (a *Agent) freezeWireGuard(ctx context.Context) error {
	if a.wireGuard == nil {
		return a.stopPrivateCores(ctx)
	}
	return a.wireGuard.transport.Freeze(ctx, a.stopPrivateCores)
}

func (a *Agent) prepareWireGuardShaping(ctx context.Context, n *spec.Node, limits []shaper.Limit) error {
	if a.wireGuard == nil {
		return nil
	}
	var devices []string
	for _, link := range n.WireGuardLinks {
		if !link.Exit {
			devices = append(devices, link.Interface())
		}
	}
	if len(devices) > 0 {
		if a.Shaper == nil {
			return fmt.Errorf("reverse WireGuard requires shared shaping")
		}
		primary, err := a.Shaper.PrimaryInterface(ctx)
		if err != nil {
			return err
		}
		devices = append(devices, primary)
	}
	// Mark ownership must be refreshed even when no private grant changed.
	// The private-access helper populated limit.Marks before this call.
	if err := a.wireGuard.shaping.Reconcile(ctx, devices, limits, a.stopPrivateCores); err != nil {
		return err
	}
	if len(devices) > 0 {
		st := a.wireGuard.shaping.Root().Status()
		a.setStatus(func(s *Status) { s.Shaper = &st })
	} else if !hasWireGuard(n) {
		a.wireGuardActive.Store(false)
	}
	return nil
}

func (a *Agent) wireGuardFailure(ctx context.Context, err error) error {
	if err == nil || (!a.wireGuardActive.Load() && !hasWireGuard(a.node)) {
		return err
	}
	// Cancellation must not preserve old authenticated sockets.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	return errors.Join(err, a.freezeWireGuard(ctx))
}

func hasWireGuardTransit(n *spec.Node) bool {
	if n != nil {
		for _, link := range n.WireGuardLinks {
			if !link.Exit {
				return true
			}
		}
	}
	return false
}

func (a *Agent) wireGuardReport(ctx context.Context) *agentproto.WireGuardReport {
	rep := &agentproto.WireGuardReport{Available: a.wireGuardReady(), Applied: !a.dirty, Links: []agentproto.WireGuardLinkStatus{}}
	if a.node == nil || !a.wireGuardActive.Load() {
		return rep
	}
	if !rep.Applied {
		return rep
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	observer := &reversewg.Linux{}
	for _, link := range a.node.WireGuardLinks {
		status, err := observer.Observe(ctx, link)
		out := agentproto.WireGuardLinkStatus{Slot: link.Slot}
		if err != nil {
			out.Error = "transport status unavailable"
		} else {
			out.Connected = status.Connected
			out.Handshake = status.Handshake
			out.Receive = status.Receive
			out.Transmit = status.Transmit
		}
		rep.Links = append(rep.Links, out)
	}
	return rep
}
