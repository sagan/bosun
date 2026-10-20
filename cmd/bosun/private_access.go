package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"github.com/zeptop-dev/bosun/internal/privatecheck"
	"github.com/zeptop-dev/bosun/internal/runas"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Preparation only creates the explicitly configured service account. It never
// rewrites an existing policy, restarts a service or modifies firewall rules.
func cmdPreparePrivateAccess(args []string) error {
	fs := flag.NewFlagSet("prepare-private-access", flag.ContinueOnError)
	path := fs.String("c", "/etc/bosun/config.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if cfg.NodeMode == spec.NodeMonitor {
		fmt.Println("private access: skipped (monitor-only)")
		return nil
	}
	if err := runas.Set(cfg.Cores.User); err != nil {
		fmt.Println("FAIL user: configured cores.user could not be prepared")
	}
	uid, _ := runas.IDs()
	guard := &egressguard.Guard{}
	r := privatecheck.Check(uid, guard.Supported(), cfg.Cores.EgressGuard != nil && !*cfg.Cores.EgressGuard, len(cfg.Cores.EgressAllow), false)
	privatecheck.Probe(context.Background(), r)
	hints := map[string]string{
		"linux": "requires Linux", "user": "set cores.user to a dedicated non-root account (for example bosun-proxy); rerun this command",
		"nft": "install nftables with your distribution package manager", "guard": "review cores.egress_guard; private access requires it enabled",
		"allow":        "review and remove global cores.egress_allow exceptions before using per-inbound grants",
		"capabilities": "bosun needs SETUID/SETGID/SETPCAP and NET_ADMIN; proxy children need NET_BIND_SERVICE/NET_ADMIN; Docker Compose: cap_add: [NET_ADMIN]",
		"kernel":       "nft list tables must succeed in the service network namespace; check kernel nftables support and container permissions",
	}
	for _, c := range r.Checks {
		if c.OK {
			fmt.Printf("OK   %s\n", c.ID)
		} else {
			fmt.Printf("FAIL %s: %s\n", c.ID, hints[c.ID])
		}
	}
	fmt.Println("Existing configuration and firewall rules were preserved. After config or container permission changes, restart bosun (proxy connections will be interrupted), then recheck in Captain.")
	if !r.Ready {
		return errors.New("private access prerequisites incomplete; other node features remain available")
	}
	return nil
}
