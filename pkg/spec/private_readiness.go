package spec

const PrivateAccessCheckKind = "private_access_check"

// PrivateAccessReadiness describes installation prerequisites, not successful
// application of an inbound or the reachability of a private destination.
type PrivateAccessReadiness struct {
	EnvironmentReady bool                 `json:"environment_ready"`
	EffectiveMode    string               `json:"effective_mode,omitempty"`
	CheckedAt        int64                `json:"checked_at"`
	Ready            bool                 `json:"ready"`
	Checks           []PrivateAccessCheck `json:"checks"`
}
type PrivateAccessCheck struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
}

// Adapter features are independent of the node firewall and process privileges.
type PrivateAccessPolicyCapabilities struct {
	Scoped         bool `json:"scoped"`
	IndependentDNS bool `json:"independent_dns"`
}
