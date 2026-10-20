// Package privatecheck performs bounded, read-only prerequisite checks.
package privatecheck

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// Capabilities checks both the current agent and the capabilities it can pass
// to a non-root child. Root inside a container is not sufficient.
func Capabilities(status string) bool {
	values := map[string]uint64{}
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 {
			n, err := strconv.ParseUint(fields[1], 16, 64)
			if err == nil {
				values[fields[0]] = n
			}
		}
	}
	const parent = uint64(1<<6 | 1<<7 | 1<<8 | 1<<12) // SETGID, SETUID, SETPCAP, NET_ADMIN
	const child = uint64(1<<10 | 1<<12)               // NET_BIND_SERVICE, NET_ADMIN
	return values["CapEff:"]&parent == parent && values["CapPrm:"]&child == child && values["CapBnd:"]&child == child
}

func Check(uid int, supported, disabled bool, allowCount int, simulated bool) *spec.PrivateAccessReadiness {
	r := &spec.PrivateAccessReadiness{CheckedAt: time.Now().Unix(), Ready: true}
	r.EffectiveMode = "dual"
	if disabled {
		r.EffectiveMode = "core_only"
	}
	add := func(id string, ok bool) {
		r.Checks = append(r.Checks, spec.PrivateAccessCheck{ID: id, OK: ok})
		r.Ready = r.Ready && ok
	}
	add("linux", runtime.GOOS == "linux" || simulated)
	add("user", uid > 0)
	add("nft", supported)
	add("guard", !disabled)
	add("allow", allowCount == 0)
	data, _ := os.ReadFile("/proc/self/status")
	add("capabilities", simulated || (runtime.GOOS == "linux" && Capabilities(string(data))))
	r.EnvironmentReady = true
	for _, c := range r.Checks {
		if c.ID != "guard" && !c.OK {
			r.EnvironmentReady = false
		}
	}
	return r
}

// Probe also checks kernel nftables access without changing any rules. Output
// is discarded: firewall contents and command errors are not report payloads.
func Probe(ctx context.Context, r *spec.PrivateAccessReadiness) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "nft", "list", "tables").Run()
	r.Checks = append(r.Checks, spec.PrivateAccessCheck{ID: "kernel", OK: err == nil})
	r.Ready = r.Ready && err == nil
	r.EnvironmentReady = r.EnvironmentReady && err == nil
}
