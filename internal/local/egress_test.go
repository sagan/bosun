package local

import (
	"context"
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
	"reflect"
	"testing"
)

func TestEgressPersistsIndependentlyAndSurvivesTakeover(t *testing.T) {
	s := openTest(t)
	list := []spec.EgressUpstream{{CIDR: "10.10.0.2", Protocol: "tcp", Port: 1080}}
	if err := s.SetEgressUpstreams(list); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouting(Routing{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	n, _, err := s.Node(context.Background())
	if err != nil || !reflect.DeepEqual(n.EgressUpstreams, list) {
		t.Fatal("policy lost", n, err)
	}
	if err := s.Adopt("https://example.com"); err != nil {
		t.Fatal(err)
	}
	if len(s.EgressUpstreams()) != 0 {
		t.Fatal("local exceptions leaked to managed state")
	}
	if err := s.Detach(nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.EgressUpstreams(), list) {
		t.Fatal("snapshot lost policy")
	}
	s.Adopt("https://example.com")
	list[0].Port = 1081
	if err := s.Detach(&agentproto.State{Node: spec.Node{EgressUpstreams: list}}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.EgressUpstreams(), list) {
		t.Fatal("managed import lost policy")
	}
}
