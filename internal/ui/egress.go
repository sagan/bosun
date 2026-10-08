package ui

import (
	"fmt"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"net/http"
)

func (s *Server) getEgress(w http.ResponseWriter, r *http.Request) {
	ok(w, map[string]any{"upstreams": s.d.Store.EgressUpstreams(), "supported": true})
}
func (s *Server) putEgress(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Upstreams *[]spec.EgressUpstream `json:"upstreams"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	if in.Upstreams == nil {
		fail(w, 400, fmt.Errorf("upstreams is required (use [] to clear)"))
		return
	}
	if err := s.d.Store.SetEgressUpstreams(*in.Upstreams); err != nil {
		fail(w, 400, err)
		return
	}
	s.getEgress(w, r)
}
