package hostmanage

import (
	"context"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func (m *machine) inspect(ctx context.Context) *spec.HostSnapshot {
	s := &spec.HostSnapshot{CheckedAt: time.Now().Unix(), Environment: "native", Items: []spec.HostItem{}}
	if !m.writable {
		s.Environment = "restricted"
	}
	supported := m.supported(ctx)
	add := func(id string, values map[string]string, known, editable bool, reason string) {
		state := "known"
		if !known {
			state = "unknown"
		}
		if !supported {
			editable = false
			reason = "requires_native_debian_systemd"
		}
		s.Items = append(s.Items, spec.HostItem{ID: id, State: state, Values: values, Editable: editable, Reason: reason})
	}
	hostname := m.read("/etc/hostname")
	running, _ := m.run(ctx, "hostname")
	add("hostname", map[string]string{"hostname": running, "persistent": hostname}, running != "", true, "")
	tp, te := m.run(ctx, "timedatectl", "show", "--property=Timezone", "--property=NTP", "--property=NTPSynchronized")
	t := props(tp)
	add("time", map[string]string{"timezone": t["Timezone"], "ntp": t["NTP"], "synchronized": t["NTPSynchronized"]}, te == nil, true, "")
	sshText, se := m.run(ctx, "sshd", "-T")
	p := kv(sshText)
	sshOK := se == nil && m.sshSupported(ctx)
	add("ssh", map[string]string{"root": p["permitrootlogin"], "password": p["passwordauthentication"], "keyboard_interactive": p["kbdinteractiveauthentication"], "public_key": p["pubkeyauthentication"]}, se == nil, sshOK, "ssh_complex_or_socket")
	listeners, le := m.run(ctx, "ss", "-H", "-lnt")
	var ports []string
	for _, port := range strings.Split(p["port"], ", ") {
		for _, line := range strings.Split(listeners, "\n") {
			f := strings.Fields(line)
			if len(f) > 3 && strings.HasSuffix(f[3], ":"+port) {
				ports = append(ports, port)
				break
			}
		}
	}
	add("port", map[string]string{"port": p["port"], "listening": strings.Join(ports, ", "), "listen_check": fmt.Sprint(le == nil)}, se == nil, sshOK, "ssh_complex_or_socket")
	var users []string
	var fingerprints []string
	groups := m.read("/etc/group")
	passwd := m.read("/etc/passwd")
	for _, line := range strings.Split(passwd, "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 || strings.Contains(f[6], "nologin") || strings.HasSuffix(f[6], "/false") {
			continue
		}
		admin := f[0] == "root" || m.exists("/etc/sudoers.d/bosun-host-"+f[0])
		for _, g := range strings.Split(groups, "\n") {
			v := strings.Split(g, ":")
			if len(v) == 4 && (v[0] == "sudo" || v[0] == "wheel") && (v[2] == f[3] || strings.Contains(","+v[3]+",", ","+f[0]+",")) {
				admin = true
			}
		}
		if admin {
			users = append(users, f[0])
			for _, path := range []string{filepath.Join(f[5], ".ssh/authorized_keys"), "/etc/ssh/bosun_authorized_keys/" + f[0]} {
				keys := []byte(m.read(path))
				for len(keys) > 0 && len(fingerprints) < 64 {
					key, _, _, rest, e := ssh.ParseAuthorizedKey(keys)
					if e != nil {
						break
					}
					fingerprints = append(fingerprints, f[0]+": "+ssh.FingerprintSHA256(key))
					keys = rest
				}
			}
		}
		if len(users) >= 32 {
			break
		}
	}
	sort.Strings(users)
	add("admin", map[string]string{"administrators": strings.Join(users, ", "), "key_fingerprints": strings.Join(fingerprints, "\n")}, passwd != "", sshOK, "ssh_complex_or_socket")
	ufw, ue := m.run(ctx, "ufw", "status")
	fw := strings.HasPrefix(ufw, "Status: active")
	backend := "ufw"
	rules := ufw
	knownFirewall := ue == nil
	if !fw {
		if tables, e := m.run(ctx, "nft", "list", "tables"); e == nil && tables != "" {
			backend = "nftables"
			rules = tables
			knownFirewall = true
		}
	}
	add("firewall", map[string]string{"backend": backend, "rules": rules}, knownFirewall, fw, "requires_active_ufw")
	f2b, fe := m.run(ctx, "fail2ban-client", "status", "sshd")
	add("fail2ban", map[string]string{"sshd": f2b}, fe == nil || m.active(ctx, "fail2ban.service"), m.active(ctx, "fail2ban.service"), "requires_fail2ban_sshd")
	upd, upErr := m.run(ctx, "apt-config", "dump")
	var config []string
	for _, line := range strings.Split(upd, "\n") {
		if strings.HasPrefix(line, "APT::Periodic::") || strings.HasPrefix(line, "Unattended-Upgrade::Automatic-Reboot ") {
			config = append(config, line)
		}
	}
	add("updates", map[string]string{"policy": strings.Join(config, "\n"), "timer_active": fmt.Sprint(m.active(ctx, "apt-daily-upgrade.timer")), "reboot_required": fmt.Sprint(m.exists("/var/run/reboot-required"))}, upErr == nil, m.exists("/usr/bin/unattended-upgrade"), "requires_unattended_upgrades")
	resolver := m.read("/etc/resolv.conf")
	var servers []string
	for _, line := range strings.Split(resolver, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	resolved := m.active(ctx, "systemd-resolved.service")
	status, _ := m.run(ctx, "resolvectl", "dns")
	add("dns", map[string]string{"servers": strings.Join(servers, ", "), "resolved": fmt.Sprint(resolved), "links": status}, len(servers) > 0, resolved || m.directResolver(), "requires_systemd_resolved")
	cc, ce := m.run(ctx, "sysctl", "-n", "net.ipv4.tcp_congestion_control")
	q, qe := m.run(ctx, "tc", "qdisc", "show")
	if qe != nil {
		q = ""
	}
	add("network", map[string]string{"bbr": cc, "queues": q, "syn_cookies": m.read("/proc/sys/net/ipv4/tcp_syncookies")}, ce == nil, true, "")
	swaps := m.read("/proc/swaps")
	mem := kv(m.read("/proc/meminfo"))
	add("swap", map[string]string{"devices": swaps, "total": mem["SwapTotal:"], "free": mem["SwapFree:"]}, swaps != "", true, "")
	// Include the source configuration bytes, not just derived status: fail stale
	// plans when a terminal/Quench changed a file while the admin reviewed it.
	revision := ""
	for _, path := range managedFiles {
		b, e := readLimited(m.path(path))
		revision += path + string(b) + fmt.Sprint(e == nil)
	}
	for _, pattern := range []string{"/etc/ssh/sshd_config.d/*.conf", "/etc/sudoers.d/*", "/etc/ssh/bosun_authorized_keys/*"} {
		paths, _ := filepath.Glob(m.path(pattern))
		if len(paths) > 128 {
			paths = paths[:128]
		}
		for _, p := range paths {
			b, e := readLimited(p)
			revision += p + string(b) + fmt.Sprint(e == nil)
		}
	}
	revision += m.read("/etc/group") + m.read("/etc/passwd")
	s.Revision = digest(revision)
	return s
}

func (m *machine) sshSupported(ctx context.Context) bool {
	if m.active(ctx, "ssh.socket") || m.active(ctx, "sshd.socket") {
		return false
	}
	// Refuse conditional configurations and custom key stores. These need a
	// context-aware policy editor; global sshd -T alone cannot verify them.
	paths := []string{m.path("/etc/ssh/sshd_config")}
	includes, _ := filepath.Glob(m.path("/etc/ssh/sshd_config.d/*.conf"))
	paths = append(paths, includes...)
	for _, p := range paths {
		b, e := readLimited(p)
		if e != nil {
			return false
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 || strings.HasPrefix(f[0], "#") {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "match", "authorizedkeyscommand", "allowusers", "denyusers", "allowgroups", "denygroups", "listenaddress":
				return false
			case "port":
				if p != m.path("/etc/ssh/sshd_config") {
					return false
				}
			case "include":
				if len(f) != 2 || f[1] != "/etc/ssh/sshd_config.d/*.conf" {
					return false
				}
			}
		}
	}
	return m.exists("/etc/ssh/sshd_config")
}

var managedFiles = []string{"/etc/resolv.conf", "/etc/hostname", "/etc/timezone", "/etc/ssh/sshd_config", "/etc/systemd/resolved.conf.d/90-bosun-host.conf", "/etc/fail2ban/jail.d/zz-bosun-host.local", "/etc/apt/apt.conf.d/99zz-bosun-host", "/etc/sysctl.d/99zz-bosun-host.conf", "/etc/fstab", "/etc/ufw/user.rules", "/etc/ufw/user6.rules"}

func (m *machine) directResolver() bool {
	st, e := os.Lstat(m.path("/etc/resolv.conf"))
	if e != nil || !st.Mode().IsRegular() {
		return false
	}
	text := strings.ToLower(m.read("/etc/resolv.conf"))
	for _, owner := range []string{"networkmanager", "resolvconf", "systemd-resolved", "generated by dhclient", "generated by cloud-init"} {
		if strings.Contains(text, owner) {
			return false
		}
	}
	return true
}
