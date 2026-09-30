package ui

import (
	"encoding/json"
	"errors"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"net/http"
	"strconv"
)

func (s *Server) registerConfigPresets(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /api/config-presets", auth(s.listConfigPresets))
	m.HandleFunc("POST /api/config-presets", auth(s.local(s.saveConfigPreset)))
	m.HandleFunc("PUT /api/config-presets/{id}", auth(s.local(s.saveConfigPreset)))
	m.HandleFunc("DELETE /api/config-presets/{id}", auth(s.local(s.deleteConfigPreset)))
	m.HandleFunc("POST /api/config-presets/preview", auth(s.local(s.previewConfigPreset)))
}
func (s *Server) listConfigPresets(w http.ResponseWriter, r *http.Request) {
	ok(w, s.d.Store.ConfigPresets())
}
func (s *Server) saveConfigPreset(w http.ResponseWriter, r *http.Request) {
	var p spec.ConfigPreset
	if err := decode(r, &p); err != nil {
		fail(w, 400, err)
		return
	}
	p.ID = 0
	if r.Method == "PUT" {
		id, e := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if e != nil || id < 1 {
			fail(w, 400, errors.New("invalid id"))
			return
		}
		p.ID = id
	}
	if err := s.d.Store.SaveConfigPreset(&p); err != nil {
		fail(w, 400, err)
		return
	}
	ok(w, p)
}
func (s *Server) deleteConfigPreset(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	storeErr(w, s.d.Store.DeleteConfigPreset(id))
}
func (s *Server) previewConfigPreset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID      int64           `json:"id"`
		Current json.RawMessage `json:"current"`
	}
	if err := decode(r, &in); err != nil {
		fail(w, 400, err)
		return
	}
	for _, p := range s.d.Store.ConfigPresets() {
		if p.ID == in.ID {
			v, e := p.Preview(in.Current)
			if e != nil {
				fail(w, 400, e)
				return
			}
			ok(w, v)
			return
		}
	}
	fail(w, 404, errors.New("preset not found"))
}
