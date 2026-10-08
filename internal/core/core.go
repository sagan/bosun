// Package core defines the interface every proxy core adapter implements and
// the registry that assigns inbounds to cores.
package core

import (
	"context"
	"errors"
	"sync"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Bundle is a rendered set of configuration files for one core.
type Bundle struct {
	Files   map[string][]byte // relative file name -> content
	Main    string            // entry file name inside Files
	Meta    map[string]string // adapter-private notes carried from Render to Start/Apply
	Payload any               // adapter-private state carried from Render to Start/Apply
}

// Capabilities is shared with the panel so selection and execution agree.
type Capabilities = spec.CoreCapabilities

// Core drives one upstream proxy binary as a child process.
//
// Lifecycle: Render -> Start; on change Render -> Apply; finally Stop.
// Stats returns per-user counters keyed by spec.User.Name.
type Core interface {
	Name() string
	Capabilities() Capabilities
	Render(node *spec.Node, inbounds []spec.Inbound, users []spec.User) (*Bundle, error)
	Start(ctx context.Context, b *Bundle) error
	Apply(ctx context.Context, b *Bundle) error
	Stop(ctx context.Context) error
	Running() bool
	Stats(ctx context.Context, reset bool) (map[string]spec.Traffic, error)
}

// Registry holds the enabled cores in registration order.
type Registry struct {
	mu    sync.RWMutex
	cores map[string]Core
	order []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{cores: map[string]Core{}}
}

// Register adds a core. Registration order is the default preference order.
func (r *Registry) Register(c Core) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.cores[c.Name()]; dup {
		panic("core registered twice: " + c.Name())
	}
	r.cores[c.Name()] = c
	r.order = append(r.order, c.Name())
}

// Get returns a core by name.
func (r *Registry) Get(name string) (Core, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.cores[name]
	return c, ok
}

// Names returns core names in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

// Assign splits inbounds by the core that will serve each one. An inbound's
// explicit Core wins if that core supports the protocol; otherwise the first
// registered core that supports it is used. Unsatisfiable inbounds are an error.
func (r *Registry) Assign(inbounds []spec.Inbound) (map[string][]spec.Inbound, error) {
	out, unsupported := r.Split(inbounds)
	for _, ib := range inbounds {
		if reason, ok := unsupported[ib.Tag]; ok {
			return nil, errors.New(reason)
		}
	}
	return out, nil
}

// Split is Assign for a running agent: inbounds no enabled core can serve
// are returned by tag with the reason instead of failing the whole set, so
// one stray inbound (say snell on a node without snell-server) never keeps
// the others from being applied.
func (r *Registry) Split(inbounds []spec.Inbound) (byCore map[string][]spec.Inbound, unsupported map[string]string) {
	byCore = map[string][]spec.Inbound{}
	unsupported = map[string]string{}
	for _, ib := range inbounds {
		name, err := r.pick(ib)
		if err != nil {
			unsupported[ib.Tag] = err.Error()
			continue
		}
		byCore[name] = append(byCore[name], ib)
	}
	return byCore, unsupported
}

// Candidates returns the enabled adapters in configured priority order.
func (r *Registry) Candidates() []spec.CoreCandidate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]spec.CoreCandidate, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, spec.CoreCandidate{Name: name, Capabilities: r.cores[name].Capabilities()})
	}
	return out
}

func (r *Registry) pick(ib spec.Inbound) (string, error) {
	return spec.SelectCore(ib, r.Candidates())
}

// InboundStatser is implemented by cores that count traffic per inbound
// (xray and sing-box through their stats APIs).
type InboundStatser interface {
	InboundStats(ctx context.Context, reset bool) (map[string]spec.Traffic, error)
}

// OutboundStatser is implemented by cores that count traffic per outbound.
type OutboundStatser interface {
	OutboundStats(ctx context.Context, reset bool) (map[string]spec.Traffic, error)
}

// OnlineTracker is implemented by cores that can report which client IPs
// each user currently connects from. Not every upstream core exposes this:
// Xray and the official Hysteria server do, sing-box and mita do not.
type OnlineTracker interface {
	Online(ctx context.Context) (map[string][]string, error)
}

// Replace publishes a validated instance without changing preference order.
// nil removes a newly enabled instance when activation has to roll back.
func (r *Registry) Replace(name string, c Core) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c == nil {
		delete(r.cores, name)
		for i, n := range r.order {
			if n == name {
				r.order = append(r.order[:i], r.order[i+1:]...)
				break
			}
		}
		return
	}
	if _, ok := r.cores[name]; !ok {
		r.order = append(r.order, name)
	}
	r.cores[name] = c
}
