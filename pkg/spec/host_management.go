package spec

import (
	"errors"
	"regexp"
	"strings"
)

const HostManagementKind = "host_manage"
const HostManagementMinimumVersion = "v0.71.0"
const HostManagementTTL = 300

// Host management is a closed set of operations, never a remote shell.
type HostRequest struct {
	Action      string            `json:"action"`
	Section     string            `json:"section,omitempty"`
	Values      map[string]string `json:"values,omitempty"`
	Revision    string            `json:"revision,omitempty"`
	Transaction string            `json:"transaction,omitempty"`
	Verified    bool              `json:"verified,omitempty"`
}
type HostJobParams struct {
	HostRequest
	ExpiresAt int64 `json:"expires_at"`
}
type HostItem struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Values   map[string]string `json:"values"`
	Editable bool              `json:"editable"`
	Reason   string            `json:"reason,omitempty"`
}
type HostPending struct {
	ID       string `json:"id"`
	Section  string `json:"section"`
	Deadline int64  `json:"deadline"`
	Phase    string `json:"phase"`
}
type HostSnapshot struct {
	CheckedAt   int64        `json:"checked_at"`
	Environment string       `json:"environment"`
	Revision    string       `json:"revision"`
	Items       []HostItem   `json:"items"`
	Pending     *HostPending `json:"pending,omitempty"`
}
type HostResult struct {
	State   *HostSnapshot `json:"state,omitempty"`
	Outcome string        `json:"outcome"`
	Message string        `json:"message,omitempty"`
}

var hostHex = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (r HostRequest) Validate() error {
	bad := errors.New("invalid host management request")
	switch r.Action {
	case "inspect":
		if r.Section != "" || len(r.Values) > 0 || r.Revision != "" || r.Transaction != "" || r.Verified {
			return bad
		}
	case "confirm", "rollback":
		if !hostHex.MatchString(r.Transaction) || r.Section != "" || len(r.Values) > 0 || r.Revision != "" || (r.Action == "confirm" && !r.Verified) {
			return bad
		}
	case "apply":
		fields := map[string]string{"hostname": "hostname", "time": "timezone ntp", "ssh": "root password", "port": "port", "admin": "user public_key", "firewall": "port protocol source", "fail2ban": "enabled bantime findtime maxretry", "updates": "enabled", "dns": "servers", "network": "bbr security", "swap": "size_mb"}
		allowed, ok := fields[r.Section]
		if !ok || !hostHex.MatchString(r.Revision) || r.Transaction != "" || r.Verified || len(r.Values) == 0 {
			return bad
		}
		for k, v := range r.Values {
			if !strings.Contains(" "+allowed+" ", " "+k+" ") || len(v) > 8192 || strings.ContainsAny(v, "\x00\r\n") {
				return bad
			}
		}
	default:
		return bad
	}
	return nil
}
