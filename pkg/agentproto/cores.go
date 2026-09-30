package agentproto

import (
	"cmp"
	"slices"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// CoreCandidates reconstructs the node's registration order. Legacy reports
// only have Running/Version, so their availability remains unknown.
func CoreCandidates(cores map[string]CoreStatus) []spec.CoreCandidate {
	var out []spec.CoreCandidate
	for name, c := range cores {
		if c.Capabilities != nil {
			out = append(out, spec.CoreCandidate{Name: name, Capabilities: *c.Capabilities})
		}
	}
	slices.SortFunc(out, func(a, b spec.CoreCandidate) int {
		if n := cmp.Compare(cores[a.Name].Priority, cores[b.Name].Priority); n != 0 {
			return n
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return out
}
