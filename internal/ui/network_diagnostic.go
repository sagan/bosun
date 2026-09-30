package ui

import (
	"net/http"

	"github.com/zeptop-dev/bosun/internal/netdiag"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (s *Server) networkDiagnostic(w http.ResponseWriter, r *http.Request) {
	if err := http.NewCrossOriginProtection().Check(r); err != nil {
		fail(w, 403, err)
		return
	}
	var in spec.DiagnosticRequest
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if err := in.Validate(); err != nil {
		fail(w, 400, err)
		return
	}
	// The normal request log records the route and outcome, never URL query
	// strings or diagnostic output. The authenticated local admin initiated it.
	ok(w, netdiag.Default.Run(r.Context(), in))
}
