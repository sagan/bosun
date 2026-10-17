// Package reversewg manages a reverse WireGuard transport.
package reversewg

import (
	"fmt"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

type Config = spec.WireGuardLink

// PeerConfig is sent only through stdin. It must never enter command arguments,
// errors, reports, or diagnostic logs.
func peerConfig(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	allowed := "0.0.0.0/0, ::/0"
	if c.Exit {
		allowed = c.Address(false, false) + "/32, " + c.Address(false, true) + "/128"
	}
	s := fmt.Sprintf("[Interface]\nPrivateKey = %s\nListenPort = %d\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", c.PrivateKey, c.ListenPort, c.PeerKey, allowed)
	if c.Exit {
		s += "Endpoint = " + c.Endpoint + "\nPersistentKeepalive = 25\n"
	}
	return s, nil
}
