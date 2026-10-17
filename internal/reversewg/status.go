package reversewg

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Status contains transport diagnostics only. These counters include protocol
// overhead and must not be submitted as subscriber billing traffic.
type Status struct {
	Slot      int    `json:"slot"`
	Connected bool   `json:"connected"`
	Handshake int64  `json:"handshake,omitempty"`
	Receive   uint64 `json:"receive"`
	Transmit  uint64 `json:"transmit"`
}

// ParseStatus consumes only "latest-handshakes" and "transfer", never "dump"
// (which exposes the interface's private key). Match the expected peer so an
// old interface or a key rotation cannot falsely confirm the desired state.
// A recent handshake demonstrates a reachable peer, not Internet/LAN health.
func ParseStatus(c Config, handshake, transfer string, now time.Time) (Status, error) {
	st := Status{Slot: c.Slot}
	if err := c.Validate(); err != nil {
		return st, err
	}
	parse := func(raw string, n int) ([]string, error) {
		lines := strings.Split(strings.TrimSpace(raw), "\n")
		if len(lines) != 1 {
			return nil, fmt.Errorf("unexpected WireGuard peer count")
		}
		fields := strings.Fields(lines[0])
		if len(fields) != n || fields[0] != c.PeerKey {
			return nil, fmt.Errorf("WireGuard peer does not match desired connection")
		}
		return fields, nil
	}
	h, err := parse(handshake, 2)
	if err != nil {
		return st, err
	}
	t, err := parse(transfer, 3)
	if err != nil {
		return st, err
	}
	stamp, err := strconv.ParseInt(h[1], 10, 64)
	if err != nil || stamp < 0 {
		return st, fmt.Errorf("invalid WireGuard handshake time")
	}
	rx, e1 := strconv.ParseUint(t[1], 10, 64)
	tx, e2 := strconv.ParseUint(t[2], 10, 64)
	if e1 != nil || e2 != nil {
		return st, fmt.Errorf("invalid WireGuard transfer counters")
	}
	st.Handshake, st.Receive, st.Transmit = stamp, rx, tx
	age := now.Unix() - stamp
	st.Connected = stamp > 0 && age >= 0 && age <= 180
	return st, nil
}

// Observe reads diagnostic fields only; command errors never include wg output.
func (l *Linux) Observe(ctx context.Context, c Config) (Status, error) {
	h, err := l.command(ctx, "wg", "show", c.Interface(), "latest-handshakes")
	if err != nil {
		return Status{Slot: c.Slot}, err
	}
	x, err := l.command(ctx, "wg", "show", c.Interface(), "transfer")
	if err != nil {
		return Status{Slot: c.Slot}, err
	}
	return ParseStatus(c, string(h), string(x), time.Now())
}
