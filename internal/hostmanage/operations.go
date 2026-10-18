package hostmanage

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/zeptop-dev/bosun/pkg/spec"
	"golang.org/x/crypto/ssh"
)

var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var usernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

func number(v string, min, max int) (int, error) {
	n, e := strconv.Atoi(v)
	if e != nil || n < min || n > max {
		return 0, errors.New("numeric value out of range")
	}
	return n, nil
}
func boolean(v string) bool                      { return v == "true" || v == "false" }
func cmd(name string, args ...string) invocation { return invocation{name, args} }
func (g *manager) ensureDir(path string) error {
	p := g.m.path(path)
	if e := os.Mkdir(p, 0755); e != nil && !os.IsExist(e) {
		return e
	}
	return safeDir(p)
}
func sshConfig(original string, settings map[string]string) string {
	const begin = "# BEGIN BOSUN HOST MANAGEMENT\n"
	const end = "# END BOSUN HOST MANAGEMENT\n"
	if strings.HasPrefix(original, begin) {
		if _, rest, ok := strings.Cut(original, end); ok {
			original = rest
		}
	}
	// Own a small first-value block only. Existing directives and includes remain.
	order := []string{"Port", "PermitRootLogin", "PasswordAuthentication", "KbdInteractiveAuthentication", "PubkeyAuthentication", "AuthorizedKeysFile"}
	// Port is multi-valued in OpenSSH: remove original top-level Port lines so
	// the managed list is authoritative. The backup keeps the untouched original.
	var originalLines []string
	for _, line := range strings.Split(original, "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && strings.EqualFold(f[0], "Port") {
			continue
		}
		originalLines = append(originalLines, line)
	}
	original = strings.Join(originalLines, "\n")
	var b strings.Builder
	b.WriteString(begin)
	for _, k := range order {
		if v := settings[k]; v != "" {
			for _, value := range strings.Split(v, "\n") {
				b.WriteString(k + " " + value + "\n")
			}
		}
	}
	b.WriteString(end)
	b.WriteString(original)
	return b.String()
}
func (g *manager) sshSettings(ctx context.Context) (string, map[string]string, error) {
	raw, e := readLimited(g.m.path("/etc/ssh/sshd_config"))
	if e != nil {
		return "", nil, e
	}
	out, e := g.m.run(ctx, "sshd", "-T")
	if e != nil {
		return "", nil, e
	}
	p := kv(out)
	return string(raw), map[string]string{"Port": strings.ReplaceAll(p["port"], ", ", "\n"), "PermitRootLogin": p["permitrootlogin"], "PasswordAuthentication": p["passwordauthentication"], "KbdInteractiveAuthentication": p["kbdinteractiveauthentication"], "PubkeyAuthentication": p["pubkeyauthentication"], "AuthorizedKeysFile": p["authorizedkeysfile"]}, nil
}
func (g *manager) plan(ctx context.Context, r spec.HostRequest) (*transaction, error) {
	t := &transaction{Section: r.Section, Values: r.Values}
	v := r.Values
	add := func(path, text string) { t.Files = append(t.Files, fileChange{Path: path, After: []byte(text)}) }
	bad := errors.New("invalid values for host operation")
	switch r.Section {
	case "hostname":
		if !hostnamePattern.MatchString(v["hostname"]) {
			return nil, bad
		}
		old, e := g.m.run(ctx, "hostname")
		if e != nil {
			return nil, e
		}
		add("/etc/hostname", v["hostname"]+"\n")
		t.Do = []invocation{cmd("hostname", v["hostname"])}
		t.Undo = []invocation{cmd("hostname", old)}
	case "time":
		zone := v["timezone"]
		if zone == "" || strings.HasPrefix(zone, "/") || strings.Contains(zone, "..") || !regexp.MustCompile(`^[A-Za-z0-9_+/-]+$`).MatchString(zone) || !g.m.exists("/usr/share/zoneinfo/"+zone) || !boolean(v["ntp"]) {
			return nil, bad
		}
		old, e := g.m.run(ctx, "timedatectl", "show", "--property=Timezone", "--property=NTP")
		if e != nil {
			return nil, e
		}
		p := props(old)
		if p["Timezone"] == "" || p["NTP"] == "" {
			return nil, bad
		}
		t.Do = []invocation{cmd("timedatectl", "set-timezone", zone), cmd("timedatectl", "set-ntp", v["ntp"])}
		t.Undo = []invocation{cmd("timedatectl", "set-timezone", p["Timezone"]), cmd("timedatectl", "set-ntp", p["NTP"])}
	case "port", "ssh", "admin":
		original, settings, e := g.sshSettings(ctx)
		if e != nil {
			return nil, e
		}
		switch r.Section {
		case "port":
			if _, e = number(v["port"], 1, 65535); e != nil {
				return nil, e
			}
			if strings.Contains("\n"+settings["Port"]+"\n", "\n"+v["port"]+"\n") {
				return nil, errors.New("new port is already configured")
			}
			listeners, e := g.m.run(ctx, "ss", "-H", "-lnt")
			if e != nil {
				return nil, e
			}
			for _, line := range strings.Split(listeners, "\n") {
				f := strings.Fields(line)
				if len(f) > 3 && strings.HasSuffix(f[3], ":"+v["port"]) {
					return nil, errors.New("new port is already in use")
				}
			}
			// An active host firewall must already allow the new port. Do not guess
			// how cloud/provider rules or foreign nftables chains should be rewritten.
			ufw, _ := g.m.run(ctx, "ufw", "status")
			if strings.HasPrefix(ufw, "Status: active") && !strings.Contains(ufw, v["port"]+"/tcp") {
				return nil, errors.New("allow the new TCP port in the firewall before SSH migration")
			}
			if _, jailErr := g.m.run(ctx, "fail2ban-client", "status", "sshd"); jailErr == nil {
				return nil, errors.New("pause the sshd jail through host management before changing SSH ports; re-enable after migration")
			}
			settings["Port"] += "\n" + v["port"]
		case "ssh":
			if (v["root"] != "no" && v["root"] != "prohibit-password") || (v["password"] != "yes" && v["password"] != "no") {
				return nil, bad
			}
			if v["password"] == "no" || v["root"] == "no" {
				if !g.readyAdmin(ctx) {
					return nil, errors.New("verify a non-root administrator with a public key before restricting SSH")
				}
			}
			settings["PermitRootLogin"] = v["root"]
			settings["PasswordAuthentication"] = v["password"]
			settings["KbdInteractiveAuthentication"] = "no"
			settings["PubkeyAuthentication"] = "yes"
		case "admin":
			user := v["user"]
			if !usernamePattern.MatchString(user) || user == "root" {
				return nil, bad
			}
			key, _, options, rest, e := ssh.ParseAuthorizedKey([]byte(v["public_key"]))
			if e != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || key.Type() == "ssh-dss" {
				return nil, errors.New("one modern public key without options is required")
			}
			// The root-owned key store avoids races and symlinks in user-owned homes.
			if e = g.ensureDir("/etc/ssh/bosun_authorized_keys"); e != nil {
				return nil, e
			}
			if e = g.ensureDir("/etc/sudoers.d"); e != nil {
				return nil, e
			}
			exists := false
			for _, line := range strings.Split(g.m.read("/etc/passwd"), "\n") {
				f := strings.Split(line, ":")
				if len(f) == 7 && f[0] == user {
					uid, _ := strconv.Atoi(f[2])
					if uid < 1000 || strings.Contains(f[6], "nologin") || strings.HasSuffix(f[6], "false") {
						return nil, errors.New("only regular login users can be managed")
					}
					exists = true
				}
			}
			if !exists {
				t.Do = append(t.Do, cmd("useradd", "--create-home", "--shell", "/bin/bash", user))
			}
			keyPath := "/etc/ssh/bosun_authorized_keys/" + user
			old := g.m.read(keyPath)
			line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
			if old != "" {
				old += "\n"
			}
			if !strings.Contains(old, line) {
				old += line + "\n"
			}
			add(keyPath, old)
			add("/etc/sudoers.d/bosun-host-"+user, user+" ALL=(ALL:ALL) NOPASSWD: ALL\n")
			t.Files[len(t.Files)-1].Mode = 0440
			if settings["AuthorizedKeysFile"] != ".ssh/authorized_keys .ssh/authorized_keys2" && settings["AuthorizedKeysFile"] != ".ssh/authorized_keys" && !strings.Contains(settings["AuthorizedKeysFile"], "/etc/ssh/bosun_authorized_keys/%u") {
				return nil, errors.New("custom AuthorizedKeysFile requires manual review")
			}
			if !strings.Contains(settings["AuthorizedKeysFile"], "/etc/ssh/bosun_authorized_keys/%u") {
				settings["AuthorizedKeysFile"] += " /etc/ssh/bosun_authorized_keys/%u"
			}
			t.Do = append(t.Do, cmd("visudo", "-cf", "/etc/sudoers"))
			// On rollback, remove only the grant and managed key file. A newly created
			// locked account/home is retained; never destroy files a user may have made.
		}
		add("/etc/ssh/sshd_config", sshConfig(original, settings))
		t.Do = append(t.Do, cmd("sshd", "-t"), cmd("systemctl", "reload", "ssh.service"))
		t.Undo = append(t.Undo, cmd("sshd", "-t"), cmd("systemctl", "reload", "ssh.service"))
	case "firewall":
		if _, e := number(v["port"], 1, 65535); e != nil {
			return nil, e
		}
		if v["protocol"] != "tcp" && v["protocol"] != "udp" {
			return nil, bad
		}
		if v["source"] != "any" {
			p, e := netip.ParsePrefix(v["source"])
			if e != nil {
				return nil, bad
			}
			v["source"] = p.Masked().String()
		}
		// Capture only UFW's user rules. Never flush nft or touch bosun-owned chains.
		for _, path := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"} {
			b, e := readLimited(g.m.path(path))
			if e != nil {
				return nil, e
			}
			add(path, string(b))
		}
		t.Do = []invocation{cmd("ufw", "allow", "proto", v["protocol"], "from", v["source"], "to", "any", "port", v["port"], "comment", "bosun-host")}
		t.Undo = []invocation{cmd("ufw", "reload")}
	case "fail2ban":
		if !boolean(v["enabled"]) {
			return nil, bad
		}
		for _, k := range []string{"bantime", "findtime"} {
			if _, e := number(v[k], 60, 604800); e != nil {
				return nil, e
			}
		}
		if _, e := number(v["maxretry"], 1, 100); e != nil {
			return nil, e
		}
		out, e := g.m.run(ctx, "sshd", "-T")
		if e != nil {
			return nil, e
		}
		ports := kv(out)["port"]
		if ports == "" {
			return nil, bad
		}
		add("/etc/fail2ban/jail.d/zz-bosun-host.local", "[sshd]\nenabled = "+v["enabled"]+"\nport = "+ports+"\nbantime = "+v["bantime"]+"\nfindtime = "+v["findtime"]+"\nmaxretry = "+v["maxretry"]+"\n")
		t.Do = []invocation{cmd("fail2ban-client", "-t"), cmd("systemctl", "restart", "fail2ban.service")}
		t.Undo = []invocation{cmd("systemctl", "restart", "fail2ban.service")}
	case "updates":
		if !boolean(v["enabled"]) {
			return nil, bad
		}
		enabled := "0"
		if v["enabled"] == "true" {
			enabled = "1"
		}
		add("/etc/apt/apt.conf.d/99zz-bosun-host", "APT::Periodic::Update-Package-Lists \""+enabled+"\";\nAPT::Periodic::Unattended-Upgrade \""+enabled+"\";\nUnattended-Upgrade::Automatic-Reboot \"false\";\n")
		// Existing distribution timers are required; do not claim an enabled policy
		// while the scheduler is stopped, or alter another operator's timer policy.
		if v["enabled"] == "true" && !g.m.active(ctx, "apt-daily-upgrade.timer") {
			return nil, errors.New("start the distribution apt-daily-upgrade.timer before enabling the policy")
		}
	case "dns":
		parts := strings.Fields(strings.ReplaceAll(v["servers"], ",", " "))
		if len(parts) < 1 || len(parts) > 4 {
			return nil, bad
		}
		for _, p := range parts {
			ip, e := netip.ParseAddr(p)
			if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
				return nil, bad
			}
		}
		if g.m.active(ctx, "systemd-resolved.service") {
			if e := g.ensureDir("/etc/systemd/resolved.conf.d"); e != nil {
				return nil, e
			}
			add("/etc/systemd/resolved.conf.d/90-bosun-host.conf", "[Resolve]\nDNS="+strings.Join(parts, " ")+"\n")
			t.Do = []invocation{cmd("systemctl", "restart", "systemd-resolved.service")}
			t.Undo = []invocation{cmd("systemctl", "restart", "systemd-resolved.service")}
		} else if g.m.directResolver() {
			var lines []string
			for _, line := range strings.Split(g.m.read("/etc/resolv.conf"), "\n") {
				f := strings.Fields(line)
				if len(f) == 0 || f[0] != "nameserver" {
					lines = append(lines, line)
				}
			}
			for _, ip := range parts {
				lines = append(lines, "nameserver "+ip)
			}
			add("/etc/resolv.conf", strings.Join(lines, "\n")+"\n")
		} else {
			return nil, errors.New("resolver configuration is externally managed")
		}

	case "network":
		if v["bbr"] != "bbr" && v["bbr"] != "cubic" {
			return nil, bad
		}
		if !boolean(v["security"]) {
			return nil, bad
		}
		available, e := g.m.run(ctx, "sysctl", "-n", "net.ipv4.tcp_available_congestion_control")
		if e != nil || !strings.Contains(" "+available+" ", " "+v["bbr"]+" ") {
			return nil, errors.New("requested congestion algorithm is not available in the running kernel")
		}
		pairs := [][2]string{{"net.ipv4.tcp_congestion_control", v["bbr"]}}
		if v["security"] == "true" {
			pairs = append(pairs, [2]string{"net.ipv4.tcp_syncookies", "1"}, [2]string{"net.ipv4.conf.all.accept_redirects", "0"}, [2]string{"net.ipv4.conf.default.accept_redirects", "0"}, [2]string{"net.ipv4.conf.all.send_redirects", "0"}, [2]string{"net.ipv4.conf.default.send_redirects", "0"}, [2]string{"net.ipv4.conf.all.accept_source_route", "0"}, [2]string{"net.ipv4.conf.default.accept_source_route", "0"}, [2]string{"net.ipv6.conf.all.accept_redirects", "0"}, [2]string{"net.ipv6.conf.default.accept_redirects", "0"})
		}
		text := g.m.read("/etc/sysctl.d/99zz-bosun-host.conf")
		for _, pair := range pairs {
			old, e := g.m.run(ctx, "sysctl", "-n", pair[0])
			if e != nil {
				continue
			}
			text += "\n" + pair[0] + " = " + pair[1]
			t.Do = append(t.Do, cmd("sysctl", "-w", pair[0]+"="+pair[1]))
			t.Undo = append(t.Undo, cmd("sysctl", "-w", pair[0]+"="+old))
		}
		add("/etc/sysctl.d/99zz-bosun-host.conf", strings.TrimSpace(text)+"\n")
	case "swap":
		// A dedicated file only; never resize or disable provider/Quench swap.
		mb, e := number(v["size_mb"], 0, 16384)
		if e != nil || mb != 0 && mb < 256 {
			return nil, bad
		}
		path := "/var/lib/bosun-host.swap"
		var disk syscall.Statfs_t
		if e := syscall.Statfs(g.m.path("/var/lib"), &disk); e != nil {
			return nil, errors.New("cannot check swap allocation space")
		}
		free := uint64(disk.Bavail) * uint64(disk.Bsize)
		reserve := max(uint64(512<<20), free/10)
		if free < uint64(mb)*(1<<20)+reserve {
			return nil, errors.New("insufficient free space; swap allocation must leave at least 512 MiB and ten percent free")
		}
		fstab := g.m.read("/etc/fstab")
		exists := g.m.exists(path)
		if mb == 0 {
			return nil, errors.New("removing active swap requires a maintenance window; this operation only creates a dedicated swap file")
		}
		if exists {
			return nil, errors.New("managed swap already exists; existing swap is preserved")
		}
		if strings.Contains(fstab, path) {
			return nil, errors.New("swap path already referenced by fstab")
		}
		// Disk allocation and zeroing are intentionally not delegated to an
		// unbounded shell; fallocate/mkswap fail safely on unsupported filesystems.
		t.Do = []invocation{cmd("fallocate", "-l", strconv.Itoa(mb)+"M", path), cmd("chmod", "0600", path), cmd("mkswap", path), cmd("swapon", path)}
		t.Undo = nil
		add("/etc/fstab", fstab+"\n"+path+" none swap sw 0 0\n")
	default:
		return nil, bad
	}
	return t, nil
}

func (g *manager) readyAdmin(ctx context.Context) bool {
	for _, line := range strings.Split(g.m.read("/etc/passwd"), "\n") {
		f := strings.Split(line, ":")
		if len(f) != 7 || f[0] == "root" {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		if uid < 1000 || strings.Contains(f[6], "nologin") {
			continue
		}
		keys := g.m.read("/etc/ssh/bosun_authorized_keys/" + f[0])
		if keys == "" {
			keys = g.m.read(filepath.Join(f[5], ".ssh/authorized_keys"))
		}
		if keys == "" {
			continue
		}
		if _, _, _, _, e := ssh.ParseAuthorizedKey([]byte(keys)); e != nil {
			continue
		}
		if out, e := g.m.run(ctx, "sudo", "-n", "-u", f[0], "sudo", "-n", "id", "-u"); e == nil && strings.TrimSpace(out) == "0" {
			return true
		}
	}
	return false
}
func (g *manager) verify(ctx context.Context, t *transaction) error {
	switch t.Section {
	case "hostname":
		v, e := g.m.run(ctx, "hostname")
		if e != nil || v != t.Values["hostname"] {
			return errors.New("hostname verification failed")
		}
	case "ssh", "port", "admin":
		out, e := g.m.run(ctx, "sshd", "-T")
		if e != nil {
			return errors.New("SSH configuration verification failed")
		}
		p := kv(out)
		if t.Section == "ssh" && (p["permitrootlogin"] != t.Values["root"] && !(t.Values["root"] == "prohibit-password" && p["permitrootlogin"] == "without-password") || p["passwordauthentication"] != t.Values["password"] || p["kbdinteractiveauthentication"] != "no") {
			return errors.New("effective SSH policy differs from request")
		}
		if t.Section == "port" {
			port := t.Values["port"]
			if !strings.Contains(", "+p["port"]+", ", ", "+port+", ") {
				return errors.New("SSH port did not become effective")
			}
			s, e := g.m.run(ctx, "ss", "-H", "-lnt")
			if e != nil || !strings.Contains(s, ":"+port+" ") {
				return errors.New("new SSH port is not listening")
			}
		}
		if t.Section == "admin" {
			if _, e = g.m.run(ctx, "sudo", "-n", "-u", t.Values["user"], "sudo", "-n", "true"); e != nil {
				return errors.New("administrator sudo verification failed")
			}
		}
	case "dns":
		if _, e := g.m.run(ctx, "getent", "ahosts", "example.com"); e != nil {
			return errors.New("DNS resolution verification failed")
		}

	case "fail2ban":
		if t.Values["enabled"] == "true" {
			if _, e := g.m.run(ctx, "fail2ban-client", "status", "sshd"); e != nil {
				return errors.New("sshd jail did not start")
			}
		}
	case "time":
		s, e := g.m.run(ctx, "timedatectl", "show", "--property=Timezone")
		if e != nil || props(s)["Timezone"] != t.Values["timezone"] {
			return errors.New("timezone verification failed")
		}
	case "swap":
		if !strings.Contains(g.m.read("/proc/swaps"), "/var/lib/bosun-host.swap") {
			return errors.New("swap did not become active")
		}
	}
	return nil
}
func (g *manager) finalize(ctx context.Context, t *transaction) error {
	if t.Section == "port" {
		original, settings, e := g.sshSettings(ctx)
		if e != nil {
			return e
		}
		settings["Port"] = t.Values["port"]
		next := []byte(sshConfig(original, settings))
		for i := range t.Files {
			if t.Files[i].Path == "/etc/ssh/sshd_config" {
				t.Files[i].Interim = t.Files[i].After
				t.Files[i].After = next
			}
		}
		// Persist intended final state before mutation so recovery recognizes it.
		if e = g.save("pending.json", t); e != nil {
			return e
		}
		if e = atomic(g.m.path("/etc/ssh/sshd_config"), next, 0600); e != nil {
			return e
		}
		if e = g.commands(ctx, []invocation{cmd("sshd", "-t"), cmd("systemctl", "reload", "ssh.service")}); e != nil {
			return e
		}
	}
	return g.verify(ctx, t)
}
