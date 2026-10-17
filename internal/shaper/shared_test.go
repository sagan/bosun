package shaper

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestSharedJournalRejectsSymlinkAndBroadPermissions(t *testing.T) {
	s := &Shared{Dir: t.TempDir()}
	target := filepath.Join(t.TempDir(), "foreign")
	if err := os.WriteFile(target, []byte(`["eth0"]`), 0600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(s.Dir, "shared-shaper.json")
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.load(); err == nil {
		t.Fatal("followed symlink")
	}
	if err := s.save([]string{"eth0"}); err == nil {
		t.Fatal("replaced symlink")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(`["eth0"]`), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.load(); err == nil {
		t.Fatal("accepted readable journal")
	}
}

func TestSharedRejectsForeignIFBBeforeMutation(t *testing.T) {
	for _, inventory := range []string{
		`[{"ifname":"ifb-bosun-up","group":61381,"linkinfo":{"info_kind":"dummy"}}]`,
		`[{"ifname":"ifb-bosun-up","group":0,"linkinfo":{"info_kind":"ifb"}}]`,
	} {
		s := &Shared{Dir: t.TempDir(), Legacy: &Shaper{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name != "ip" || strings.Join(args, " ") != "-j -d link show" {
				t.Fatalf("mutation before preflight: %s %v", name, args)
			}
			return []byte(inventory), nil
		}}}
		if err := s.Apply(context.Background(), []string{"eth0"}, nil); err == nil {
			t.Fatal("accepted foreign IFB")
		}
		if _, err := os.Stat(filepath.Join(s.Dir, "shared-shaper.json")); !os.IsNotExist(err) {
			t.Fatal("claimed foreign resource")
		}
	}
}

func TestSharedFingerprintTracksHandlesAndInterfaceRecreation(t *testing.T) {
	index := 3
	handle := "0x10001"
	s := &Shared{Legacy: &Shaper{Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return json.Marshal([]map[string]any{{"ifname": "eth0", "ifindex": index}})
		}
		return []byte(`[{"pref":49151,"kind":"fw","options":{"fw":{"mark":"` + handle + `","mask":"0xffffffff"},"actions":[{"kind":"mirred","to_dev":"ifb-bosun"}]}}]`), nil
	}}}
	ctx := context.Background()
	first, err := s.fingerprint(ctx, []string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	index++
	next, err := s.fingerprint(ctx, []string{"eth0"})
	if err != nil || first == next {
		t.Fatal("missed interface recreation", err)
	}
	index--
	handle = "0x10002"
	next, err = s.fingerprint(ctx, []string{"eth0"})
	if err != nil || first == next {
		t.Fatal("missed mark replacement", err)
	}
}

func TestSharedRootConcurrent(t *testing.T) {
	s := &Shared{}
	first := s.Root()
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			if s.Root() != first {
				t.Error("different root")
			}
		})
	}
	wg.Wait()
}

func TestSharedNoopKeepsFilters(t *testing.T) {
	ctx := context.Background()
	mutations := 0
	s := &Shared{Dir: t.TempDir(), Legacy: &Shaper{Interface: "eth0", Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "-j" {
			return []byte(`[{"ifname":"eth0","ifindex":2},{"ifname":"ifb-bosun-up","ifindex":3,"group":61381,"linkinfo":{"info_kind":"ifb"}}]`), nil
		}
		if name == "tc" && len(args) > 0 && args[0] == "-j" {
			return []byte(`[]`), nil
		}
		mutations++
		return nil, nil
	}}}
	if err := s.Apply(ctx, []string{"eth0"}, nil); err != nil {
		t.Fatal(err)
	}
	before := mutations
	if err := s.Apply(ctx, []string{"eth0"}, nil); err != nil {
		t.Fatal(err)
	}
	if mutations != before {
		t.Fatal("unchanged state rebuilt shaping")
	}
}

func TestSharedOrphanRedirectRecoveryRejectsLiveForeignTarget(t *testing.T) {
	for _, tc := range []struct {
		to                          string
		targetExists, owned, wantOK bool
	}{
		{"*", false, true, true}, {"*", true, true, false}, {"foreign0", false, true, false}, {"*", false, false, false},
	} {
		s := &Shared{Legacy: &Shaper{Run: func(_ context.Context, _ string, _ ...string) ([]byte, error) {
			return []byte(`[{"protocol":"all","pref":49151,"chain":0,"kind":"fw","options":{"fw":{"mark":"0x10001","mask":"0xffffffff"},"actions":[{"kind":"mirred","direction":"egress","mirred_action":"redirect","to_dev":"` + tc.to + `"}]}}]`), nil
		}}}
		links := map[string]sharedLink{}
		if tc.targetExists {
			links[ifbDev] = sharedLink{}
		}
		err := s.checkFilters(context.Background(), "eth0", "ingress", tc.owned, links)
		if (err == nil) != tc.wantOK {
			t.Fatalf("case %+v: %v", tc, err)
		}
	}
}

func TestSharedLegacyFWJSONRetainsEnforcement(t *testing.T) {
	for _, tc := range []struct {
		handle, target string
		ok             bool
	}{
		{"0x10001", "ifb-bosun", true}, {"0x10001/0xffffffff", "ifb-bosun", true},
		{"0x10001/0xffff", "ifb-bosun", false}, {"0x10001", "foreign0", false},
		{"0x100000000", "ifb-bosun", false}, {"0x10001/0x100000000", "ifb-bosun", false},
		{"0x10001 classid 1:2", "ifb-bosun", false},
	} {
		raw := `[{"protocol":"all","pref":49151,"kind":"fw","chain":0,"options":{handle ` + tc.handle + `
  "actions":[{"kind":"mirred","direction":"egress","mirred_action":"redirect","to_dev":"` + tc.target + `"}]}}]`
		s := &Shared{Legacy: &Shaper{Run: func(context.Context, string, ...string) ([]byte, error) { return []byte(raw), nil }}}
		err := s.checkFilters(context.Background(), "eth0", "ingress", true, map[string]sharedLink{ifbDev: {}})
		if (err == nil) != tc.ok {
			t.Fatalf("%+v: %v", tc, err)
		}
		if tc.ok {
			list, err := s.filters(context.Background(), "eth0", "ingress")
			if err != nil || list[0].Options.FW.Mark != "0x10001" {
				t.Fatal("lost selector", err)
			}
		}
	}
	raw := []byte(`{"quoted":"{handle 0x1 \"actions\": something"}`)
	if string(normalizeLegacyFWJSON(raw)) != string(raw) {
		t.Fatal("rewrote quoted text")
	}
}

func TestSharedRecognizesCompleteLegacyIngressInventory(t *testing.T) {
	raw := `[{"protocol":"all","pref":1,"kind":"matchall","chain":0},{"protocol":"all","pref":1,"kind":"matchall","chain":0,"options":{"handle":1,"actions":[{"kind":"connmark"},{"kind":"mirred","direction":"egress","mirred_action":"redirect","to_dev":"ifb-bosun"}]}}]`
	s := &Shared{Legacy: &Shaper{Run: func(context.Context, string, ...string) ([]byte, error) { return []byte(raw), nil }}}
	if err := s.checkFilters(context.Background(), "eth0", "ingress", false, nil); err != nil {
		t.Fatal(err)
	}
	raw = `[{"protocol":"all","pref":1,"kind":"matchall","chain":0}]`
	if err := s.checkFilters(context.Background(), "eth0", "ingress", false, nil); err == nil {
		t.Fatal("unproven legacy header accepted")
	}
}

func TestSharedFiltersKeepExplicitHookDirection(t *testing.T) {
	raw := `[{"ingress":true,"protocol":"all","pref":7,"kind":"matchall","chain":0}]`
	s := &Shared{Legacy: &Shaper{Run: func(context.Context, string, ...string) ([]byte, error) { return []byte(raw), nil }}}
	if err := s.checkFilters(context.Background(), "eth0", "egress", false, nil); err != nil {
		t.Fatal("opposite hook treated as egress", err)
	}
	if err := s.checkFilters(context.Background(), "eth0", "ingress", false, nil); err == nil {
		t.Fatal("foreign ingress ignored")
	}
	raw = `[{"ingress":true,"egress":true,"protocol":"all","pref":7,"kind":"matchall"}]`
	if _, err := s.filters(context.Background(), "eth0", "egress"); err == nil {
		t.Fatal("ambiguous direction accepted")
	}
}

func TestSharedReplacesOnlyEmptyLegacyHook(t *testing.T) {
	for _, nonempty := range []bool{false, true} {
		var mutations []string
		s := &Shared{Legacy: &Shaper{Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			command := strings.Join(args, " ")
			if command == "-j qdisc show dev eth0" {
				return []byte(`[{"kind":"htb"},{"kind":"ingress"}]`), nil
			}
			if command == "-j filter show dev eth0 ingress" {
				if nonempty {
					return []byte(`[{"kind":"matchall","pref":7}]`), nil
				}
				return []byte(`[]`), nil
			}
			mutations = append(mutations, command)
			return nil, nil
		}}}
		err := s.prepareHooks(context.Background(), "eth0")
		if nonempty {
			if err == nil || len(mutations) > 0 {
				t.Fatal("modified nonempty hook", err, mutations)
			}
		} else if err != nil || strings.Join(mutations, ";") != "qdisc delete dev eth0 ingress;qdisc replace dev eth0 clsact" {
			t.Fatal("modified root or missed ingress transition", err, mutations)
		}
	}
}
