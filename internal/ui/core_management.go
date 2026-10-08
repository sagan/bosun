package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zeptop-dev/bosun/internal/authutil"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type coreOperation struct {
	ID     string              `json:"id"`
	DoneAt *time.Time          `json:"done_at,omitempty"`
	Error  string              `json:"error,omitempty"`
	Result *spec.CoreInventory `json:"result,omitempty"`
}

func (s *Server) coreInventory(w http.ResponseWriter, r *http.Request) {
	ag := s.currentAgent()
	if ag == nil {
		fail(w, 503, errors.New("agent is starting"))
		return
	}
	ok(w, ag.CoreInventory())
}

func (s *Server) manageCore(w http.ResponseWriter, r *http.Request) {
	var req spec.CoreRequest
	if decode(r, &req) != nil {
		fail(w, 400, errors.New("bad core request"))
		return
	}
	if err := req.Validate(); err != nil {
		fail(w, 400, err)
		return
	}
	ag := s.currentAgent()
	if ag == nil || ag.CoreManager == nil {
		fail(w, 409, errors.New("core management is unavailable"))
		return
	}
	if _, err := ag.CoreManager.Validate(req); err != nil {
		fail(w, 409, err)
		return
	}
	s.mu.Lock()
	for _, op := range s.coreOps {
		if op.DoneAt == nil {
			s.mu.Unlock()
			fail(w, 409, errors.New("another core operation is in progress"))
			return
		}
	}
	if s.coreOps == nil {
		s.coreOps = map[string]coreOperation{}
	}
	// No credentials in results; a bounded set lives for this agent session.
	if len(s.coreOps) >= 20 {
		for id, op := range s.coreOps {
			if op.DoneAt != nil {
				delete(s.coreOps, id)
			}
		}
	}
	id := authutil.Token(16)
	s.coreOps[id] = coreOperation{ID: id}
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(spec.CoreManagementTTL)*time.Second)
		defer cancel()
		err := ag.ManageCore(ctx, req)
		now := time.Now()
		op := coreOperation{ID: id, DoneAt: &now, Result: ag.CoreInventory()}
		if err != nil {
			op.Error = err.Error()
		}
		s.mu.Lock()
		s.coreOps[id] = op
		s.mu.Unlock()
	}()
	ok(w, map[string]string{"id": id})
}

func (s *Server) coreOperation(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	op, found := s.coreOps[r.PathValue("job")]
	s.mu.Unlock()
	if !found {
		fail(w, 404, errors.New("operation not found"))
		return
	}
	ok(w, op)
}
