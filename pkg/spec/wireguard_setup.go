package spec

import "errors"

const WireGuardSetupKind = "wireguard_setup"
const WireGuardSetupTTL = 300

type WireGuardSetupRequest struct {
	Action    string `json:"action"`
	ExpiresAt int64  `json:"expires_at"`
}

func (r WireGuardSetupRequest) Validate() error {
	if (r.Action != "check" && r.Action != "install") || r.ExpiresAt <= 0 {
		return errors.New("invalid WireGuard setup request")
	}
	return nil
}

// Checks describe this running agent's environment; package installation cannot
// repair core identity, capabilities, guard policy or missing proxy cores.
type WireGuardSetup struct {
	CheckedAt   int64                `json:"checked_at"`
	Checks      []PrivateAccessCheck `json:"checks"`
	Installable bool                 `json:"installable"`
	Packages    []string             `json:"packages"`
	Manager     string               `json:"manager,omitempty"`
}
type WireGuardSetupResult struct {
	Status    *WireGuardSetup `json:"status"`
	ErrorCode string          `json:"error_code,omitempty"`
}
