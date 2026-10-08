package local

import (
	"errors"
	"fmt"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func checkIngressListener(gs []Ingress, id, listen string, port int) error {
	for _, g := range gs {
		if id == "" && g.RequireIngress {
			return errors.New("this node requires an ingress for every inbound and forward")
		}
		if id != "" && g.ID == id {
			if err := g.Ports().Check(port); err != nil {
				return fmt.Errorf("%s: %w", g.Name, err)
			}
			return spec.CheckIngressListen(g.BindIP, listen)
		}
	}
	if id != "" {
		return errors.New("ingress not found")
	}
	return nil
}

// Call with s.mu held, before replacing or deleting any ingress.
func (s *Store) checkIngressesLocked(gs []Ingress) error {
	for _, ib := range s.st.Inbounds {
		if err := checkIngressListener(gs, ib.IngressID, ib.Listen, ib.Port); err != nil {
			return fmt.Errorf("inbound %s: %w", ib.Tag, err)
		}
		for _, g := range gs {
			if g.ID == ib.IngressID {
				if err := ib.Inbound.CheckCoreListen(g.BindIP); err != nil {
					return err
				}
				if err := g.Ports().CheckInbound(ib.Inbound); err != nil {
					return fmt.Errorf("inbound %s: %w", ib.Tag, err)
				}
			}
		}
	}
	for _, f := range s.st.Forwards {
		if err := checkForwardFamily(gs, f); err != nil {
			return fmt.Errorf("forward %s: %w", f.Tag, err)
		}
		if err := checkIngressListener(gs, f.IngressID, f.Listen, f.Port); err != nil {
			return fmt.Errorf("forward %s: %w", f.Tag, err)
		}
	}
	return nil
}

func (s *Store) resolvedForwardsLocked() []spec.Forward {
	out := append([]spec.Forward{}, s.st.Forwards...)
	for i := range out {
		if out[i].IngressID != "" && out[i].Listen == "" {
			if g, ok := s.ingressLocked(out[i].IngressID); ok {
				out[i].Listen = g.BindIP
			}
		}
		out[i].IngressID = ""
	}
	return out
}

func checkForwardFamily(gs []Ingress, f spec.Forward) error {
	if f.Listen == "" {
		for _, g := range gs {
			if g.ID == f.IngressID {
				f.Listen = g.BindIP
			}
		}
	}
	return f.ValidateTargets()
}
