package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/internal/shaper"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) privateAccessReady() bool {
	uid, _ := runas.IDs()
	return uid > 0 && a.Egress != nil && a.Egress.Supported() && !a.EgressDisabled && len(a.EgressAllow) == 0
}

func (a *Agent) stopPrivateCores(ctx context.Context) error {
	var errs []error
	for _, name := range a.reg.Names() {
		c, _ := a.reg.Get(name)
		if c.Running() {
			errs = append(errs, c.Stop(ctx))
		}
	}
	a.setStatus(func(s *Status) { a.appliedCores = map[string][]string{} })
	return errors.Join(errs...)
}

// preparePrivateAccess runs BEFORE any core starts. Tightening permissions
// stops old sockets before replacing nft grants, so a removed/reassigned mark
// cannot inherit another inbound's permission. A guard/shaper failure leaves
// these cores stopped; dirty apply will retry without falling back to global
// exceptions. Stable policies do not restart on every heartbeat.
func (a *Agent) preparePrivateAccess(ctx context.Context, node *spec.Node, limits []shaper.Limit) error {
	active := node.HasPrivateAccess()
	if !active && !a.privatePolicyActive {
		// After a process restart memory cannot tell whether the old nft
		// table still carries grants. Reconcile it before starting any
		// core, including when the first received policy has no grants.
		if a.privatePolicyKey == "" && a.Egress != nil && a.Egress.Supported() {
			if err := a.applyEgress(ctx, node); err != nil {
				return errors.Join(err, a.stopPrivateCores(ctx))
			}
			a.privatePolicyKey = "null"
		}
		return nil
	}
	grants, err := node.PrivateGrants(a.users)
	if err == nil && active && !a.privateAccessReady() {
		err = fmt.Errorf("private access requires Linux nft, a non-root core account and enabled egress guard without global CIDR exceptions")
	}
	if err != nil {
		return errors.Join(err, a.stopPrivateCores(ctx))
	}
	key, _ := json.Marshal(grants)
	if string(key) != a.privatePolicyKey {
		// Flush current counters before a security-mandated reconnect.
		for _, name := range a.reg.Names() {
			c, _ := a.reg.Get(name)
			if c.Running() {
				a.report(ctx)
				break
			}
		}
		if err := a.stopPrivateCores(ctx); err != nil {
			return err
		}
	}
	for i := range limits {
		for _, g := range grants {
			if g.UserID == limits[i].UserID {
				limits[i].Marks = append(limits[i].Marks, g.Mark)
			}
		}
	}
	if err := a.applyEgress(ctx, node); err != nil {
		return errors.Join(err, a.stopPrivateCores(ctx))
	}
	if len(limits) > 0 && a.Shaper != nil {
		if err := a.Shaper.Apply(ctx, limits); err != nil {
			return errors.Join(err, a.stopPrivateCores(ctx))
		}
	}
	a.privatePolicyKey = string(key)
	a.privatePolicyActive = active
	return nil
}
