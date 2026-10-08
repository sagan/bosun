package local

import "github.com/zeptop-dev/bosun/pkg/spec"

func (s *Store) EgressUpstreams() []spec.EgressUpstream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]spec.EgressUpstream{}, s.st.EgressUpstreams...)
}
func (s *Store) SetEgressUpstreams(list []spec.EgressUpstream) error {
	if err := spec.ValidateEgressUpstreams(list); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.st.EgressUpstreams
	s.st.EgressUpstreams = append([]spec.EgressUpstream{}, list...)
	if err := s.commit(); err != nil {
		s.st.EgressUpstreams = previous
		return err
	}
	return nil
}
