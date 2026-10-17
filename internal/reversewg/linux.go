package reversewg

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/wg"
)

// Linux executes only fixed binaries and validated arguments, without a shell.
// Command output is intentionally excluded from errors: wg may echo keys.
type Linux struct {
	Run func(context.Context, Command) ([]byte, error)
}

func (l *Linux) run(ctx context.Context, c Command) ([]byte, error) {
	if l.Run != nil {
		return l.Run(ctx, c)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Stdin = strings.NewReader(c.Stdin)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("reverse WireGuard %s command failed: %w", c.Name, err)
	}
	return out, nil
}
func (l *Linux) command(ctx context.Context, name string, args ...string) ([]byte, error) {
	return l.run(ctx, Command{Name: name, Args: args})
}
func (l *Linux) Supported() bool {
	if l.Run != nil {
		return true
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return false
	}
	// Root inside a container need not have CAP_NET_ADMIN. Advertising it
	// would let Captain create a topology this process cannot apply.
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	capable := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			caps, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			capable = err == nil && caps&(1<<12) != 0
		}
	}
	if !capable {
		return false
	}
	for _, bin := range []string{"ip", "wg", "nft", "sysctl"} {
		if _, err := exec.LookPath(bin); err != nil {
			return false
		}
	}
	return true
}

type linkInfo struct {
	Name  string   `json:"ifname"`
	Alias string   `json:"ifalias"`
	Group any      `json:"group"`
	MTU   int      `json:"mtu"`
	Flags []string `json:"flags"`
	Info  struct {
		Kind string `json:"info_kind"`
	} `json:"linkinfo"`
	Addresses []struct {
		Local string `json:"local"`
	} `json:"addr_info"`
}
type ruleInfo struct {
	Priority int    `json:"priority"`
	Source   string `json:"src"`
	Table    any    `json:"table"`
}
type routeInfo struct {
	Destination string `json:"dst"`
	Device      string `json:"dev"`
	Table       any    `json:"table"`
	Type        string `json:"type"`
	Metric      int    `json:"metric"`
}
type inventory struct {
	links  []linkInfo
	rules  [2][]ruleInfo
	routes [2][]routeInfo
}

func tableID(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case string:
		if x == "main" {
			return 254
		}
		if x == "local" {
			return 255
		}
		n, _ := strconv.Atoi(x)
		return n
	case nil:
		return 254
	}
	return -1
}
func address(s string) netip.Addr {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr()
	}
	a, _ := netip.ParseAddr(s)
	return a
}
func (l *Linux) inventory(ctx context.Context) (inventory, error) {
	var in inventory
	read := func(dst any, args ...string) error {
		b, err := l.command(ctx, "ip", args...)
		if err != nil {
			return err
		}
		if json.Unmarshal(b, dst) != nil {
			return fmt.Errorf("invalid ip inventory response")
		}
		return nil
	}
	if err := read(&in.links, "-j", "-d", "link", "show"); err != nil {
		return in, err
	}
	var addresses []linkInfo
	if err := read(&addresses, "-j", "address", "show"); err != nil {
		return in, err
	}
	for i := range in.links {
		for _, a := range addresses {
			if in.links[i].Name == a.Name {
				in.links[i].Addresses = a.Addresses
			}
		}
	}
	for i, family := range []string{"-4", "-6"} {
		if err := read(&in.rules[i], "-j", family, "rule", "show"); err != nil {
			return in, err
		}
		if err := read(&in.routes[i], "-j", family, "route", "show", "table", "all"); err != nil {
			return in, err
		}
	}
	return in, nil
}
func alias(c Config) string { return fmt.Sprintf("bosun-reversewg:%d", c.Slot) }

func (l *Linux) Preflight(ctx context.Context, old []Ownership, cs []Config) error {
	if !l.Supported() {
		return fmt.Errorf("reverse WireGuard requires root on Linux with ip, wg, nft and sysctl")
	}
	in, err := l.inventory(ctx)
	if err != nil {
		return err
	}
	owned := map[string]Ownership{}
	for _, r := range old {
		owned[r.config().Interface()] = r
	}
	for _, link := range in.links {
		if r, ok := owned[link.Name]; ok && !ownsLink(link, r.config()) {
			return fmt.Errorf("WireGuard interface ownership conflict")
		}
	}
	for _, c := range cs {
		for _, link := range in.links {
			_, ours := owned[link.Name]
			if link.Name == c.Interface() && !ours {
				return fmt.Errorf("WireGuard interface name already in use")
			}
			if !ours {
				for _, a := range link.Addresses {
					if a.Local == c.Address(false, false) || a.Local == c.Address(true, false) || a.Local == c.Address(false, true) || a.Local == c.Address(true, true) {
						return fmt.Errorf("WireGuard tunnel address already in use")
					}
				}
			}
		}
		_, ours := owned[c.Interface()]
		for i := range 2 {
			for _, r := range in.rules[i] {
				if r.Priority == 12000+c.Slot || tableID(r.Table) == c.Table() {
					if !ours || c.Exit || r.Priority != 12000+c.Slot || tableID(r.Table) != c.Table() || address(r.Source).String() != c.Address(false, i == 1) {
						return fmt.Errorf("WireGuard routing rule conflict")
					}
				}
			}
			for _, r := range in.routes[i] {
				if tableID(r.Table) == c.Table() {
					if !ours || c.Exit || !ownedRoute(c, r) {
						return fmt.Errorf("WireGuard routing table conflict")
					}
					continue
				}
				if _, ok := owned[r.Device]; ok {
					continue
				}
				if p, err := routePrefix(r.Destination); err == nil && p.Bits() > 0 && (p.Contains(address(c.Address(false, i == 1))) || p.Contains(address(c.Address(true, i == 1)))) {
					return fmt.Errorf("WireGuard tunnel network overlaps a host route")
				}
			}
		}
	}
	return nil
}
func ownedRoute(c Config, r routeInfo) bool {
	if r.Destination != "default" && r.Destination != "0.0.0.0/0" && r.Destination != "::/0" {
		return false
	}
	return (r.Type == "unreachable" && r.Metric == 32767) || (r.Device == c.Interface() && r.Metric == 1 && (r.Type == "" || r.Type == "unicast"))
}
func (l *Linux) Firewall(ctx context.Context, script string) error {
	// Listing tables distinguishes an absent table from permission/netlink
	// failure. Never retry a failed atomic replacement as an additive append.
	b, err := l.command(ctx, "nft", "-j", "list", "tables")
	if err != nil {
		return err
	}
	var listing struct {
		NFTables []struct {
			Table *struct {
				Family string `json:"family"`
				Name   string `json:"name"`
			} `json:"table"`
		} `json:"nftables"`
	}
	if json.Unmarshal(b, &listing) != nil {
		return fmt.Errorf("invalid nft table inventory")
	}
	for _, entry := range listing.NFTables {
		if entry.Table != nil && entry.Table.Family == "inet" && entry.Table.Name == firewallTable {
			script = "delete table inet " + firewallTable + "\n" + script
			break
		}
	}
	_, err = l.run(ctx, Command{Name: "nft", Args: []string{"-f", "-"}, Stdin: script})
	return err
}
func (l *Linux) Remove(ctx context.Context, o Ownership) error {
	c := o.config()
	in, err := l.inventory(ctx)
	if err != nil {
		return err
	}
	for _, link := range in.links {
		if link.Name == c.Interface() {
			if !ownsLink(link, c) {
				return fmt.Errorf("refusing to remove foreign WireGuard interface")
			}
		}
	}
	for i, family := range []string{"-4", "-6"} {
		for _, r := range in.rules[i] {
			if r.Priority == 12000+c.Slot || tableID(r.Table) == c.Table() {
				if c.Exit || r.Priority != 12000+c.Slot || tableID(r.Table) != c.Table() || address(r.Source).String() != c.Address(false, i == 1) {
					return fmt.Errorf("refusing to remove foreign routing rule")
				}
				if _, err := l.command(ctx, "ip", family, "rule", "delete", "priority", strconv.Itoa(r.Priority), "from", r.Source, "lookup", strconv.Itoa(c.Table())); err != nil {
					return err
				}
			}
		}
		for _, r := range in.routes[i] {
			if tableID(r.Table) == c.Table() {
				if c.Exit || !ownedRoute(c, r) {
					return fmt.Errorf("refusing to remove foreign routing table")
				}
				args := []string{family, "route", "delete"}
				if r.Type == "unreachable" {
					args = append(args, "unreachable")
				}
				args = append(args, "default", "table", strconv.Itoa(c.Table()), "metric", strconv.Itoa(r.Metric))
				if r.Device != "" {
					args = append(args, "dev", r.Device)
				}
				if _, err := l.command(ctx, "ip", args...); err != nil {
					return err
				}
			}
		}
	}
	for _, link := range in.links {
		if link.Name == c.Interface() {
			_, err := l.command(ctx, "ip", "link", "delete", "dev", c.Interface())
			return err
		}
	}
	return nil
}
func (l *Linux) Create(ctx context.Context, c Config) error {
	if c.Exit {
		if err := l.enableForwarding(ctx); err != nil {
			return err
		}
	}
	plan, err := CreatePlan(c)
	if err != nil {
		return err
	}
	for _, cmd := range plan {
		if _, err := l.run(ctx, cmd); err != nil {
			return err
		}
	}
	return nil
}
func (l *Linux) Healthy(ctx context.Context, cs []Config) bool {
	in, err := l.inventory(ctx)
	if err != nil {
		return false
	}
	for _, c := range cs {
		found := false
		for _, link := range in.links {
			if link.Name == c.Interface() && ownsLink(link, c) && link.Alias == alias(c) && link.MTU == c.MTU && slices.Contains(link.Flags, "UP") {
				v4, v6 := false, false
				for _, a := range link.Addresses {
					v4 = v4 || a.Local == c.Address(c.Exit, false)
					v6 = v6 || a.Local == c.Address(c.Exit, true)
				}
				found = v4 && v6
			}
		}
		if !found {
			return false
		}
		pub, err := wg.PublicKey(c.PrivateKey)
		if err != nil {
			return false
		}
		actual, err := l.command(ctx, "wg", "show", c.Interface(), "public-key")
		if err != nil || strings.TrimSpace(string(actual)) != pub {
			return false
		}
		peers, err := l.command(ctx, "wg", "show", c.Interface(), "peers")
		if err != nil || strings.TrimSpace(string(peers)) != c.PeerKey {
			return false
		}
		allowed, err := l.command(ctx, "wg", "show", c.Interface(), "allowed-ips")
		if err != nil {
			return false
		}
		parts := strings.Fields(string(allowed))
		want := []string{"0.0.0.0/0", "::/0"}
		if c.Exit {
			want = []string{c.Address(false, false) + "/32", c.Address(false, true) + "/128"}
		}
		if len(parts) != 3 || parts[0] != c.PeerKey || !slices.Contains(parts[1:], want[0]) || !slices.Contains(parts[1:], want[1]) {
			return false
		}
		if c.ListenPort > 0 {
			port, err := l.command(ctx, "wg", "show", c.Interface(), "listen-port")
			if err != nil || strings.TrimSpace(string(port)) != strconv.Itoa(c.ListenPort) {
				return false
			}
		}
		if c.Exit {
			for i := range 2 {
				found := false
				for _, r := range in.routes[i] {
					found = found || (r.Device == c.Interface() && tableID(r.Table) == 254 && address(r.Destination).String() == c.Address(false, i == 1))
				}
				if !found {
					return false
				}
			}
		}
		if !c.Exit {
			for i := range 2 {
				rule, route, stop := false, false, false
				for _, r := range in.rules[i] {
					rule = rule || (r.Priority == 12000+c.Slot && tableID(r.Table) == c.Table() && address(r.Source).String() == c.Address(false, i == 1))
				}
				for _, r := range in.routes[i] {
					if tableID(r.Table) == c.Table() && ownedRoute(c, r) {
						route = route || r.Device == c.Interface()
						stop = stop || r.Type == "unreachable"
					}
				}
				if !rule || !route || !stop {
					return false
				}
			}
		}
	}
	return true
}

func routePrefix(s string) (netip.Prefix, error) {
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.ParsePrefix(s)
}

func ownsLink(link linkInfo, c Config) bool {
	return link.Name == c.Interface() && tableID(link.Group) == c.Table() && link.Info.Kind == "wireguard" && (link.Alias == "" || link.Alias == alias(c))
}

// Enable routing without disabling previously accepted IPv6 router adverts.
// Do not restore forwarding=0 on cleanup: other services may now rely on it.
func (l *Linux) enableForwarding(ctx context.Context) error {
	read := func(key string) (string, error) {
		b, err := l.command(ctx, "sysctl", "-n", key)
		return strings.TrimSpace(string(b)), err
	}
	set := func(key, value string) error {
		_, err := l.command(ctx, "sysctl", "-q", "-w", key+"="+value)
		return err
	}
	v6, err := read("net.ipv6.conf.all.forwarding")
	if err != nil {
		return err
	}
	if v6 != "1" {
		in, err := l.inventory(ctx)
		if err != nil {
			return err
		}
		names := []string{"all", "default"}
		for _, link := range in.links {
			names = append(names, link.Name)
		}
		for _, name := range names {
			// Interface names come from the kernel, but sysctl path separators
			// still need validation before interpolating them into an argument.
			if name == "" || strings.ContainsAny(name, "/= \t\r\n") {
				return fmt.Errorf("unsupported interface name for IPv6 forwarding")
			}
			key := "net/ipv6/conf/" + name + "/accept_ra"
			value, err := read(key)
			if err != nil {
				return err
			}
			if value == "1" {
				if err := set(key, "2"); err != nil {
					return err
				}
			}
		}
		if err := set("net.ipv6.conf.all.forwarding", "1"); err != nil {
			return err
		}
	}
	v4, err := read("net.ipv4.ip_forward")
	if err != nil {
		return err
	}
	if v4 != "1" {
		return set("net.ipv4.ip_forward", "1")
	}
	return nil
}

// EmergencyFreeze is used when the journal cannot be trusted. It changes no
// links/routes and does not adopt resources. The atomic group marker plus the
// reserved device name identifies the transport that must stop forwarding.
func (l *Linux) EmergencyFreeze(ctx context.Context) error {
	if !l.Supported() {
		return fmt.Errorf("cannot freeze WireGuard without Linux network tools")
	}
	in, err := l.inventory(ctx)
	if err != nil {
		return err
	}
	var records []Ownership
	for _, link := range in.links {
		slot, err := strconv.Atoi(strings.TrimPrefix(link.Name, "bwg"))
		if err != nil || slot < 1 || slot > 16383 {
			continue
		}
		c := Config{Slot: slot}
		if ownsLink(link, c) {
			records = append(records, Ownership{Slot: slot})
		}
	}
	if len(records) == 0 {
		return nil
	}
	rules, err := FrozenFirewall(records)
	if err != nil {
		return err
	}
	return l.Firewall(ctx, rules)
}
