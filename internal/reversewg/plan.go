package reversewg

import (
	"fmt"
	"strconv"
)

// Command is executed without a shell. Stdin can contain key material and must
// not be logged. Production reconciliation must first establish ownership and
// install Firewall atomically; this plan alone is NOT a reconciliation API.
type Command struct {
	Name  string
	Args  []string
	Stdin string
}

// CreatePlan builds a fresh interface inside an already guarded network
// namespace. A terminal unreachable route prevents a missing WireGuard device
// from falling through to the main routing table. The output guard is still
// necessary: policy rules can also disappear, and the local table runs first.
func CreatePlan(c Config) ([]Command, error) {
	peer, err := peerConfig(c)
	if err != nil {
		return nil, err
	}
	dev := c.Interface()
	var cmds []Command
	add := func(name string, args ...string) { cmds = append(cmds, Command{Name: name, Args: args}) }
	// Group and MTU are installed atomically with the device. Some iproute2
	// versions silently ignore alias on link-add, so set that separately.
	add("ip", "link", "add", "dev", dev, "group", strconv.Itoa(c.Table()), "mtu", strconv.Itoa(c.MTU), "type", "wireguard")
	add("ip", "link", "set", "dev", dev, "alias", fmt.Sprintf("bosun-reversewg:%d", c.Slot))
	cmds = append(cmds, Command{Name: "wg", Args: []string{"setconf", dev, "/dev/stdin"}, Stdin: peer})
	// Loose reverse path validation is required on A: reply source addresses
	// normally resolve through the main interface, not through this link.
	add("sysctl", "-q", "-w", "net.ipv4.conf."+dev+".rp_filter=2")
	add("ip", "link", "set", "dev", dev, "up")
	for _, v6 := range []bool{false, true} {
		family, bits := "-4", "/32"
		if v6 {
			family, bits = "-6", "/128"
		}
		addr := c.Address(c.Exit, v6)
		args := []string{family, "address", "add", addr + bits, "dev", dev}
		if v6 {
			args = append(args, "nodad")
		}
		add("ip", args...)
		if c.Exit {
			add("ip", family, "route", "add", c.Address(false, v6)+bits, "dev", dev)
		} else {
			table := strconv.Itoa(c.Table())
			add("ip", family, "route", "add", "unreachable", "default", "metric", "32767", "table", table)
			add("ip", family, "route", "add", "default", "dev", dev, "metric", "1", "table", table)
			add("ip", family, "rule", "add", "priority", strconv.Itoa(12000+c.Slot), "from", addr+bits, "lookup", table)
		}
	}

	return cmds, nil
}
