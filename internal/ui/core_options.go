package ui

import (
	"fmt"
	"net/http"

	"github.com/zeptop-dev/bosun/internal/local"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (s *Server) coreOptions(w http.ResponseWriter, r *http.Request) {
	var candidates []spec.CoreCandidate
	if a := s.currentAgent(); a != nil {
		candidates = a.CoreCandidates()
	}
	ok(w, spec.PreviewCores(spec.CoreProbe(r.URL.Query()), candidates))
}

func (s *Server) checkInboundCore(ib local.Inbound) error {
	if ib.Protocol == spec.Mieru && ib.Core == "singbox-extended" && s.d.Store.Settings().MitaQuotas {
		return fmt.Errorf("extended Mieru does not support mita native quotas; disable native quotas or select mita")
	}
	if ib.Listen == "" && ib.IngressID != "" {
		if g, ok := s.d.Store.Ingress(ib.IngressID); ok {
			ib.Listen = g.BindIP
		}
	}
	if ib.PrivateAccess.Enabled() {
		a := s.currentAgent()
		if a == nil {
			return fmt.Errorf("private access needs a running supported agent")
		}
		if _, err := spec.SelectCore(ib.Inbound, a.CoreCandidates()); err != nil {
			return err
		}
	}

	if ib.Enabled {
		if a := s.currentAgent(); a != nil {
			_, err := spec.SelectCore(ib.Inbound, a.CoreCandidates())
			return err
		}
	}
	return nil
}
