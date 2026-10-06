package spec

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// PortMapping maps an inclusive local range to an equally sized public range.
// A single port is represented by LocalFrom == LocalTo. Mappings apply to
// both TCP and UDP; the provider must actually forward the protocols in use.
type PortMapping struct {
	LocalFrom  int `json:"local_from"`
	LocalTo    int `json:"local_to"`
	PublicFrom int `json:"public_from"`
}

// IngressPorts is shared by Captain and the standalone editor. Explicit
// mappings replace the legacy continuous range/offset, never extend it.
type IngressPorts struct {
	From, To, Offset int
	Reserved         []int
	Mappings         []PortMapping
}

func (p IngressPorts) Validate() error {
	if (p.From == 0) != (p.To == 0) || p.From < 0 || p.To > 65535 || p.From > p.To {
		return errors.New("port range must be from-to within 1-65535, or empty")
	}
	if p.Offset < -65534 || p.Offset > 65534 || (p.From > 0 && (p.From+p.Offset < 1 || p.To+p.Offset > 65535)) {
		return errors.New("mapped public ports must be within 1-65535")
	}
	for _, r := range p.Reserved {
		if r < 1 || r > 65535 {
			return errors.New("reserved ports must be within 1-65535")
		}
	}
	if len(p.Mappings) > 128 {
		return errors.New("at most 128 port mappings are allowed")
	}
	if len(p.Mappings) > 0 && (p.From != 0 || p.To != 0 || p.Offset != 0) {
		return errors.New("use explicit port mappings or a continuous range, not both")
	}
	for i, m := range p.Mappings {
		if m.LocalFrom < 1 || m.LocalTo < m.LocalFrom || m.LocalTo > 65535 || m.PublicFrom < 1 || m.PublicFrom > 65535 || m.PublicFrom+m.LocalTo-m.LocalFrom > 65535 {
			return fmt.Errorf("mapping %d: local and public ports must be within 1-65535", i+1)
		}
		for _, prev := range p.Mappings[:i] {
			if m.LocalFrom <= prev.LocalTo && prev.LocalFrom <= m.LocalTo {
				return errors.New("local port mapping ranges overlap")
			}
			if m.PublicFrom <= prev.PublicFrom+prev.LocalTo-prev.LocalFrom && prev.PublicFrom <= m.PublicFrom+m.LocalTo-m.LocalFrom {
				return errors.New("public port mapping ranges overlap")
			}
		}
	}
	return nil
}

// EntryPort returns zero when no valid mapping exists. Reserved ports still
// have a mapping (e.g. provider SSH), but cannot be used by a listener.
func (p IngressPorts) EntryPort(local int) int {
	if local < 1 || local > 65535 {
		return 0
	}
	if len(p.Mappings) > 0 {
		for _, m := range p.Mappings {
			if local >= m.LocalFrom && local <= m.LocalTo {
				return m.PublicFrom + local - m.LocalFrom
			}
		}
		return 0
	}
	if p.From > 0 && (local < p.From || local > p.To) {
		return 0
	}
	n := local + p.Offset
	if n < 1 || n > 65535 {
		return 0
	}
	return n
}

func (p IngressPorts) Check(port int) error {
	for _, r := range p.Reserved {
		if r == port {
			return fmt.Errorf("port %d is reserved (SSH or provider use)", port)
		}
	}
	if p.EntryPort(port) == 0 {
		return fmt.Errorf("port %d is outside the allowed port range or mappings", port)
	}
	return nil
}

// Mieru BOTH also binds port+1 for UDP and advertises it relative to the
// first public port. Both ports must remain inside the same mapping.
func (p IngressPorts) CheckInbound(ib Inbound) error {
	if err := p.Check(ib.Port); err != nil {
		return err
	}
	if ib.Protocol == Mieru && strings.EqualFold(ib.MieruTransport, "BOTH") {
		if err := p.Check(ib.Port + 1); err != nil {
			return err
		}
		if p.EntryPort(ib.Port+1) != p.EntryPort(ib.Port)+1 {
			return errors.New("mieru BOTH requires adjacent mapped public ports")
		}
	}
	return nil
}

// CheckIngressListen prevents overriding a selected NIC with a wildcard or
// another address. Empty listens inherit BindIP before reaching old agents.
func CheckIngressListen(bindIP, listen string) error {
	if bindIP != "" && listen != "" && !net.ParseIP(bindIP).Equal(net.ParseIP(listen)) {
		return errors.New("listen address must match the selected ingress bind address (or be empty)")
	}
	return nil
}
