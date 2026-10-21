package agent

import (
	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (a *Agent) CoreCandidates() []spec.CoreCandidate {
	out := a.reg.Candidates()
	for i := range out {
		if out[i].Capabilities.PrivateAccess {
			out[i].Capabilities.PrivateAccessPolicy = &spec.PrivateAccessPolicyCapabilities{Scoped: true, SplitRouting: out[i].Capabilities.CoreOnlyPrivateAccess, IndependentDNS: out[i].Capabilities.CoreOnlyPrivateAccess}
		}
		out[i].Capabilities.CoreOnlyPrivateAccess = out[i].Capabilities.CoreOnlyPrivateAccess && a.coreOnlyPrivateAccessReady()
		// Never advertise a transport that this installation cannot enforce.
		out[i].Capabilities.WireGuardReverse = out[i].Capabilities.WireGuardReverse && a.wireGuardReady()
		if out[i].Capabilities.PrivateAccess {
			out[i].Capabilities.PrivateAccessReadiness = a.privateAccessReadiness()
			out[i].Capabilities.PrivateAccess = out[i].Capabilities.PrivateAccessReadiness.Ready
		}
	}
	return out
}

// CoreStatus reports registration independently of liveness. An idle enabled
// core is selectable, but a failed apply must not look like a running inbound.
func (a *Agent) CoreStatus() map[string]agentproto.CoreStatus {
	a.statusMu.Lock()
	defer a.statusMu.Unlock()
	out := map[string]agentproto.CoreStatus{}
	versions := map[string]string{}
	if inventory := a.CoreInventory(); inventory != nil {
		for _, instance := range inventory.Instances {
			versions[instance.Distribution] = instance.Version
		}
	}
	for priority, c := range a.CoreCandidates() {
		adapter, _ := a.reg.Get(c.Name)
		st := agentproto.CoreStatus{Version: versions[c.Name], Running: adapter.Running(), Capabilities: &c.Capabilities, Priority: priority}
		if st.Running {
			st.Inbounds = append([]string(nil), a.appliedCores[c.Name]...)
		}
		out[c.Name] = st
	}
	return out
}
