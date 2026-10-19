package spec

// FirewallStatus describes listener rules, not end-to-end reachability or
// forwarding policy. Sources never contain credentials or remote addresses.
type FirewallStatus struct {
	Kind      string               `json:"kind"`
	Opened    int                  `json:"opened"`
	Error     string               `json:"error,omitempty"`
	CheckedAt int64                `json:"checked_at"`
	State     string               `json:"state"`
	Warning   string               `json:"warning,omitempty"`
	Rules     []FirewallRuleStatus `json:"rules"`
}
type FirewallRuleStatus struct {
	Port     int      `json:"port"`
	Protocol string   `json:"protocol"`
	Sources  []string `json:"sources"`
	State    string   `json:"state"`
	Detail   string   `json:"detail,omitempty"`
}
