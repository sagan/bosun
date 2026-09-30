package local

import (
	"encoding/json"
	"fmt"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (s *Store) ConfigPresets() []spec.ConfigPreset {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []spec.ConfigPreset{}
	raw, _ := json.Marshal(s.st.ConfigPresets)
	_ = json.Unmarshal(raw, &out)
	if out == nil {
		out = []spec.ConfigPreset{}
	}
	return out
}
func (s *Store) SaveConfigPreset(p *spec.ConfigPreset) error {
	if err := p.Normalize(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := append([]spec.ConfigPreset{}, s.st.ConfigPresets...)
	seq := s.st.PresetSequence
	if p.ID == 0 {
		if len(prev) >= 200 {
			return fmt.Errorf("at most 200 presets")
		}
		s.st.PresetSequence++
		p.ID = s.st.PresetSequence
		s.st.ConfigPresets = append(prev, *p)
	} else {
		found := false
		for i, v := range prev {
			if v.ID == p.ID {
				s.st.ConfigPresets[i] = *p
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
	}
	if err := s.commit(); err != nil {
		s.st.ConfigPresets = prev
		s.st.PresetSequence = seq
		return err
	}
	return nil
}
func (s *Store) DeleteConfigPreset(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.st.ConfigPresets
	next := []spec.ConfigPreset{}
	for _, p := range prev {
		if p.ID != id {
			next = append(next, p)
		}
	}
	if len(next) == len(prev) {
		return ErrNotFound
	}
	s.st.ConfigPresets = next
	if err := s.commit(); err != nil {
		s.st.ConfigPresets = prev
		return err
	}
	return nil
}
