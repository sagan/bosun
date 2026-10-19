package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixture struct {
	kind  string
	ufw   []string
	rich  map[string][]string
	plain string
	calls []string
	fail  bool
}

func (f *fixture) run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if name == "ufw" {
		switch strings.Join(args, " ") {
		case "status":
			if f.kind == "ufw" {
				return []byte("Status: active\n"), nil
			}
			return []byte("Status: inactive\n"), nil
		case "show added":
			return []byte("Added user rules (see 'ufw status' for running firewall):\n" + strings.Join(f.ufw, "\n")), nil
		}
		if f.fail {
			return nil, errors.New("injected mutation failure")
		}
		del := args[0] == "delete"
		if del {
			args = args[1:]
		}
		if len(args) != 4 || args[0] != "allow" || args[2] != "comment" {
			return nil, errors.New("unexpected command")
		}
		rule := "ufw allow " + args[1] + " comment '" + args[3] + "'"
		if del {
			for i, r := range f.ufw {
				if r == rule {
					f.ufw = append(f.ufw[:i], f.ufw[i+1:]...)
					break
				}
			}
		} else {
			f.ufw = append(f.ufw, rule)
		}
		return nil, nil
	}
	if name != "firewall-cmd" {
		return nil, errors.New("unexpected executable")
	}
	if args[0] == "--state" {
		if f.kind == "firewalld" {
			return []byte("running"), nil
		}
		return nil, errors.New("inactive")
	}
	if args[0] == "--get-default-zone" {
		return []byte("public"), nil
	}
	key := "runtime"
	if strings.Contains(call, "--permanent") {
		key = "permanent"
	}
	op := args[len(args)-1]
	if op == "--list-ports" {
		return []byte(f.plain), nil
	}
	if op == "--list-rich-rules" {
		return []byte(strings.Join(f.rich[key], "\n")), nil
	}
	if f.fail {
		return nil, errors.New("injected mutation failure")
	}
	if strings.HasPrefix(op, "--add-rich-rule=") {
		f.rich[key] = append(f.rich[key], strings.TrimPrefix(op, "--add-rich-rule="))
		return nil, nil
	}
	if strings.HasPrefix(op, "--remove-rich-rule=") {
		rule := strings.TrimPrefix(op, "--remove-rich-rule=")
		for i, r := range f.rich[key] {
			if r == rule {
				f.rich[key] = append(f.rich[key][:i], f.rich[key][i+1:]...)
				break
			}
		}
		return nil, nil
	}
	return nil, errors.New("unexpected command")
}
func manager(t *testing.T, kind string) (*Manager, *fixture) {
	t.Helper()
	f := &fixture{kind: kind, rich: map[string][]string{}}
	return &Manager{StateFile: filepath.Join(t.TempDir(), "firewall.json"), Run: f.run}, f
}
func TestSharedPortOwnershipAndRestart(t *testing.T) {
	m, f := manager(t, "ufw")
	ctx := context.Background()
	p := Port{Proto: "tcp", Port: 443, Source: "inbound:a"}
	p2 := p
	p2.Source = "forward:b"
	if e := m.Apply(ctx, []Port{p, p2, {Proto: "udp", Port: 443, Source: "inbound:c"}}); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 2 || m.Status().Opened != 2 {
		t.Fatalf("%+v %v", m.Status(), f.ufw)
	}
	if len(m.Status().Rules[0].Sources) != 2 {
		t.Fatal(m.Status())
	}
	if e := m.Apply(ctx, []Port{p2}); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 1 {
		t.Fatal(f.ufw)
	}
	m2 := &Manager{StateFile: m.StateFile, Run: f.run}
	if e := m2.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 0 {
		t.Fatal(f.ufw)
	}
}
func TestManualRuleNeverAdopted(t *testing.T) {
	for _, kind := range []string{"ufw", "firewalld"} {
		t.Run(kind, func(t *testing.T) {
			m, f := manager(t, kind)
			f.ufw = []string{"ufw allow 443/tcp"}
			f.plain = "443/tcp"
			p := Port{Proto: "tcp", Port: 443}
			if e := m.Apply(context.Background(), []Port{p}); e != nil {
				t.Fatal(e)
			}
			if m.Status().Rules[0].State != "external" || len(m.data.Entries) != 0 {
				t.Fatal(m.Status())
			}
			if e := m.Apply(context.Background(), nil); e != nil {
				t.Fatal(e)
			}
			for _, c := range f.calls {
				if strings.Contains(c, "delete") || strings.Contains(c, "remove-") {
					t.Fatal(c)
				}
			}
		})
	}
}
func TestExternalChangeRetained(t *testing.T) {
	m, f := manager(t, "ufw")
	ctx := context.Background()
	p := Port{Proto: "tcp", Port: 443}
	if e := m.Apply(ctx, []Port{p}); e != nil {
		t.Fatal(e)
	}
	f.ufw = append(f.ufw, "ufw allow from 192.0.2.0/24 to any port 443 proto tcp")
	if e := m.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 2 || m.Status().Rules[0].State != "retained" {
		t.Fatalf("%v %+v", f.ufw, m.Status())
	}
	// An operator taking over the exact rule by changing its comment is external.
	f.ufw = []string{"ufw allow 443/tcp comment 'operator'"}
	if e := m.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 1 {
		t.Fatal(f.ufw)
	}
}
func TestLegacyAndCorruptState(t *testing.T) {
	m, f := manager(t, "ufw")
	if e := os.WriteFile(m.StateFile, []byte(`["443/tcp"]`), 0600); e != nil {
		t.Fatal(e)
	}
	f.ufw = []string{"ufw allow 443/tcp"}
	if e := m.Apply(context.Background(), nil); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 1 || m.Status().Warning != "legacy_rules_retained" {
		t.Fatal(m.Status())
	}
	m, f = manager(t, "ufw")
	os.WriteFile(m.StateFile, []byte(`broken`), 0600)
	if e := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 443}}); e == nil {
		t.Fatal("corrupt state accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal(f.calls)
	}
}
func TestIntentFailureRetryAndDrift(t *testing.T) {
	m, f := manager(t, "ufw")
	ctx := context.Background()
	f.fail = true
	if e := m.Apply(ctx, []Port{{Proto: "tcp", Port: 443}}); e == nil {
		t.Fatal("failure hidden")
	}
	if m.Status().Rules[0].State != "error" {
		t.Fatal(m.Status())
	}
	f.fail = false
	restarted := &Manager{StateFile: m.StateFile, Run: f.run}
	if e := restarted.Apply(ctx, []Port{{Proto: "tcp", Port: 443}}); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 1 {
		t.Fatal(f.ufw)
	}
	f.ufw = nil
	if e := restarted.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	if len(f.ufw) != 1 {
		t.Fatal("missing owned rule not restored")
	}
}
func TestFirewalldOwnedRichRulesNoReload(t *testing.T) {
	m, f := manager(t, "firewalld")
	ctx := context.Background()
	f.plain = "22/tcp"
	if e := m.Apply(ctx, []Port{{Proto: "tcp", Port: 443}}); e != nil {
		t.Fatal(e)
	}
	// Manual allowance added while our distinct rich rule exists must survive.
	f.plain = "22/tcp 443/tcp"
	if e := m.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if len(f.rich["runtime"])+len(f.rich["permanent"]) != 0 {
		t.Fatal(f.rich)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "--reload") || strings.Contains(c, "--remove-port") {
			t.Fatal(c)
		}
	}
}
func TestNoFirewallAndStateFailure(t *testing.T) {
	m, _ := manager(t, "")
	if e := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 443}}); e != nil {
		t.Fatal(e)
	}
	if m.Status().State != "unavailable" {
		t.Fatal(m.Status())
	}
	m, f := manager(t, "ufw")
	os.Symlink(filepath.Join(t.TempDir(), "missing"), m.StateFile)
	if e := m.Apply(context.Background(), []Port{{Proto: "tcp", Port: 443}}); e == nil {
		t.Fatal("symlink state accepted")
	}
	if len(f.calls) > 0 {
		t.Fatal(f.calls)
	}
}

func TestFirewalldPartialFailureIsRecoverable(t *testing.T) {
	m, f := manager(t, "firewalld")
	ctx := context.Background()
	normal := f.run
	m.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "--add-rich-rule=") && !strings.Contains(strings.Join(args, " "), "--permanent") {
			return nil, errors.New("runtime unavailable")
		}
		return normal(ctx, name, args...)
	}
	if e := m.Apply(ctx, []Port{{Proto: "tcp", Port: 443}}); e == nil {
		t.Fatal("partial failure hidden")
	}
	if len(f.rich["permanent"]) != 1 || len(f.rich["runtime"]) != 0 {
		t.Fatal(f.rich)
	}
	restarted := &Manager{StateFile: m.StateFile, Run: normal}
	if e := restarted.Apply(ctx, nil); e != nil {
		t.Fatal(e)
	}
	if len(f.rich["permanent"]) != 0 {
		t.Fatal("partial persisted rule not removed")
	}
}
