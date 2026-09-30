package shaper

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
)

// Remove only the matchall filter that redirects into our private IFB. The
// ingress qdisc may hold another program's filters even after bosun stops.
// Fields follow tc's JSON output; no iproute2 implementation is embedded here.
func (s *Shaper) removeIngress(ctx context.Context, iface string) error {
	raw, err := s.run(ctx, "tc", "-j", "filter", "show", "dev", iface, "ingress")
	if err != nil {
		return err
	}
	var filters []struct {
		Protocol string `json:"protocol"`
		Pref     uint32 `json:"pref"`
		Kind     string `json:"kind"`
		Chain    uint32 `json:"chain"`
		Options  struct {
			Handle  uint32 `json:"handle"`
			Actions []struct {
				Kind      string `json:"kind"`
				Direction string `json:"direction"`
				Action    string `json:"mirred_action"`
				To        string `json:"to_dev"`
			} `json:"actions"`
		} `json:"options"`
	}
	if err := json.Unmarshal(raw, &filters); err != nil {
		return fmt.Errorf("read ingress filters: %w", err)
	}
	for _, f := range filters {
		if f.Kind != "matchall" || f.Protocol != "all" || f.Pref != 1 || f.Chain != 0 || f.Options.Handle == 0 {
			continue
		}
		for _, a := range f.Options.Actions {
			if a.Kind == "mirred" && a.Direction == "egress" && a.Action == "redirect" && a.To == ifbDev {
				if _, err := s.run(ctx, "tc", "filter", "del", "dev", iface, "ingress", "protocol", "all", "pref", "1", "chain", "0", "handle", strconv.FormatUint(uint64(f.Options.Handle), 10), "matchall"); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}
