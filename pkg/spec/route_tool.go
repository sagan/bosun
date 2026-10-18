package spec

const RouteToolMinimumVersion = "v0.70.0"

// RouteToolStatus describes the node's actual runtime, not its host OS packages.
type RouteToolStatus struct {
	Engine      string `json:"engine,omitempty"`
	Version     string `json:"version,omitempty"`
	State       string `json:"state"`
	Installable bool   `json:"installable"`
	Managed     bool   `json:"managed"`
	IPv4        string `json:"ipv4"`
	IPv6        string `json:"ipv6"`
}
