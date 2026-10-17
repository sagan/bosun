package shaper

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

const sharedUp = "ifb-bosun-up"
const sharedGroup = 61381

var sharedInterface = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

// Shared aggregates one user's marked sockets across physical and WireGuard
// devices. Both directions share one class per user; tunnel overhead has no
// subscriber mark and never enters those classes.
type Shared struct {
	Dir      string
	Legacy   *Shaper
	root     *Shaper
	mu       sync.Mutex
	rootOnce sync.Once
	applied  [32]byte
	snapshot [32]byte
	synced   bool
}

func (s *Shared) Root() *Shaper {
	s.rootOnce.Do(func() {
		s.root = &Shaper{Interface: sharedUp}
		if s.Legacy != nil {
			s.root.Run = s.Legacy.Run
		}
	})
	return s.root
}

// Apply requires the caller to quiesce affected proxy cores before changing
// the device set or limits, and to keep them stopped when Apply fails.
func (s *Shared) Apply(ctx context.Context, interfaces []string, limits []Limit) error {
	return s.Reconcile(ctx, interfaces, limits, nil)
}

// Reconcile calls quiesce before any mutation, including health repair. The
// caller keeps proxies stopped on any error. A healthy no-op never quiesces.
func (s *Shared) Reconcile(ctx context.Context, interfaces []string, limits []Limit, quiesce func(context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, err := s.load()
	if err != nil {
		return err
	}
	devs := append([]string(nil), interfaces...)
	slices.Sort(devs)
	devs = slices.Compact(devs)
	if len(devs) == 0 && len(old) == 0 {
		return nil
	}
	for _, dev := range devs {
		if !sharedInterface.MatchString(dev) || dev == sharedUp || dev == ifbDev || dev == "lo" {
			return fmt.Errorf("invalid shared shaping interface")
		}
	}
	if len(devs) > 128 {
		return fmt.Errorf("too many shared shaping interfaces")
	}
	r := s.Root()
	if !r.Supported() {
		return fmt.Errorf("shared shaping requires Linux nft and tc")
	}
	links, err := s.links(ctx)
	if err != nil {
		return err
	}
	if link, exists := links[sharedUp]; exists && (link.Group != strconv.Itoa(sharedGroup) || link.Kind != "ifb") {
		return fmt.Errorf("shared upload interface is owned by another service")
	}
	all := append(append([]string{}, old...), devs...)
	slices.Sort(all)
	all = slices.Compact(all)
	for _, dev := range all {
		if _, exists := links[dev]; !exists {
			if slices.Contains(devs, dev) {
				return fmt.Errorf("shared shaping interface is missing")
			}
			continue
		}
		for _, direction := range []string{"ingress", "egress"} {
			if err := s.checkFilters(ctx, dev, direction, slices.Contains(old, dev), links); err != nil {
				return err
			}
		}
	}
	limits = append([]Limit(nil), limits...)
	for i := range limits {
		limits[i].Marks = append([]int64(nil), limits[i].Marks...)
		slices.Sort(limits[i].Marks)
		limits[i].Marks = slices.Compact(limits[i].Marks)
	}
	slices.SortFunc(limits, func(a, b Limit) int {
		if a.UserID < b.UserID {
			return -1
		}
		if a.UserID > b.UserID {
			return 1
		}
		return 0
	})
	data, _ := json.Marshal(struct {
		Devices []string
		Limits  []Limit
	}{devs, limits})
	key := sha256.Sum256(data)
	if s.synced && s.applied == key && slices.Equal(old, devs) {
		current, err := s.fingerprint(ctx, devs)
		if err != nil {
			return err
		}
		if current == s.snapshot && (len(limits) == 0 || r.classesPresent(ctx, sharedUp, limits)) {
			return nil
		}
	}
	if quiesce != nil {
		if err := quiesce(ctx); err != nil {
			return err
		}
	}
	// Any failure below must force another full reconciliation.
	s.synced = false
	if err := s.save(all); err != nil {
		return err
	}
	// This removes legacy per-device user classes but preserves foreign root
	// qdiscs. Its cached empty state avoids removing the shared IFB on updates.
	if len(devs) > 0 && s.Legacy != nil {
		if err := s.Legacy.Apply(ctx, nil); err != nil {
			return err
		}
	}
	for _, dev := range all {
		if _, exists := links[dev]; !exists {
			continue
		}
		for _, direction := range []string{"ingress", "egress"} {
			if err := s.clearFilters(ctx, dev, direction); err != nil {
				return err
			}
		}
	}
	if len(devs) == 0 {
		// The legacy cleanup requires a real device for its tc inventory.
		// Recreate our missing IFB briefly so interrupted creation/removal is
		// retryable; the pending journal remains durable throughout.
		if _, exists := links[sharedUp]; !exists {
			if _, err := r.run(ctx, "ip", "link", "add", sharedUp, "group", strconv.Itoa(sharedGroup), "type", "ifb"); err != nil {
				return err
			}
		}
		r.mu.Lock()
		r.synced = false
		r.mu.Unlock()
		if err := r.Apply(ctx, nil); err != nil {
			return err
		}
		if _, err := r.run(ctx, "ip", "link", "delete", sharedUp); err != nil {
			return err
		}
		return s.save(nil)
	}
	if _, exists := links[sharedUp]; !exists {
		if _, err := r.run(ctx, "ip", "link", "add", sharedUp, "group", strconv.Itoa(sharedGroup), "type", "ifb"); err != nil {
			return err
		}
	}
	if _, err := r.run(ctx, "ip", "link", "set", sharedUp, "up"); err != nil {
		return err
	}
	if err := r.Apply(ctx, limits); err != nil {
		return err
	}
	if len(limits) == 0 {
		return s.finish(ctx, devs, key)
	}
	if err := r.Resync(ctx); err != nil {
		return err
	}
	if st := r.Status(); st.DownloadError != "" {
		return fmt.Errorf("shared shaping requires both upload and download support")
	}
	marks := []int64{}
	for _, limit := range limits {
		marks = append(marks, spec.SpeedMark(limit.UserID))
		marks = append(marks, limit.Marks...)
	}
	slices.Sort(marks)
	marks = slices.Compact(marks)
	for _, dev := range devs {
		// Only empty or already-owned filter lists reached this point. Keep
		// the physical root qdisc (including an operator's line limit).
		if _, err := r.run(ctx, "tc", "qdisc", "replace", "dev", dev, "clsact"); err != nil {
			return err
		}
		if _, err := r.run(ctx, "tc", "filter", "add", "dev", dev, "ingress", "protocol", "all", "pref", "49150", "matchall", "action", "connmark", "continue"); err != nil {
			return err
		}
		for _, direction := range []string{"ingress", "egress"} {
			target := sharedUp
			if direction == "ingress" {
				target = ifbDev
			}
			for _, mark := range marks {
				if _, err := r.run(ctx, "tc", "filter", "add", "dev", dev, direction, "protocol", "all", "pref", "49151", "handle", "0x"+strconv.FormatInt(mark, 16), "fw", "action", "mirred", "egress", "redirect", "dev", target); err != nil {
					return err
				}
			}
		}
	}
	return s.finish(ctx, devs, key)
}

type sharedLink struct {
	Group, Kind string
	Index       int
}

func (s *Shared) links(ctx context.Context) (map[string]sharedLink, error) {
	b, err := s.Root().run(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return nil, err
	}
	var list []struct {
		Name  string `json:"ifname"`
		Group any    `json:"group"`
		Index int    `json:"ifindex"`
		Info  struct {
			Kind string `json:"info_kind"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(b, &list) != nil {
		return nil, fmt.Errorf("invalid shared shaping link inventory")
	}
	out := map[string]sharedLink{}
	for _, l := range list {
		out[l.Name] = sharedLink{fmt.Sprint(l.Group), l.Info.Kind, l.Index}
	}
	return out, nil
}

type sharedFilter struct {
	Ingress  bool   `json:"ingress,omitempty"`
	Egress   bool   `json:"egress,omitempty"`
	Pref     int    `json:"pref"`
	Kind     string `json:"kind"`
	Protocol string `json:"protocol"`
	Chain    int    `json:"chain"`
	Options  *struct {
		Handle json.RawMessage `json:"handle"`
		FW     *struct {
			Mark string `json:"mark"`
			Mask string `json:"mask"`
		} `json:"fw"`
		Actions []struct {
			Kind      string `json:"kind"`
			To        string `json:"to_dev"`
			Direction string `json:"direction"`
			Action    string `json:"mirred_action"`
		} `json:"actions"`
	} `json:"options"`
}

func (s *Shared) filters(ctx context.Context, dev, direction string) ([]sharedFilter, error) {
	b, err := s.Root().run(ctx, "tc", "-j", "filter", "show", "dev", dev, direction)
	if err != nil {
		return nil, err
	}
	var list []sharedFilter
	if json.Unmarshal(normalizeLegacyFWJSON(b), &list) != nil {
		return nil, fmt.Errorf("invalid shared shaping filters")
	}
	// With an ingress-only qdisc, some tc versions also dump its filters
	// for an egress query. They explicitly tag those rows as ingress; do not
	// treat the same rule as belonging to both hooks (or delete the wrong one).
	filtered := list[:0]
	for _, f := range list {
		if f.Ingress && f.Egress {
			return nil, fmt.Errorf("ambiguous shared shaping filter direction")
		}
		if (direction == "egress" && f.Ingress) || (direction == "ingress" && f.Egress) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered, nil
}

// Older iproute2 prints the fw handle as plain text inside otherwise JSON
// output. Normalize only that exact token outside quoted strings; retain the
// mark and mask and let JSON decoding reject every other unexpected fragment.
var legacyFWHandle = regexp.MustCompile(`^\{handle (0x[0-9a-fA-F]+)(?:/(0x[0-9a-fA-F]+))?[ \t\r\n]+("actions"[ \t\r\n]*:)`)

func normalizeLegacyFWJSON(raw []byte) []byte {
	var out strings.Builder
	quoted, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quoted {
			out.WriteByte(c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		}
		if c == '{' {
			match := legacyFWHandle.FindSubmatchIndex(raw[i:])
			if match != nil {
				mark, markErr := strconv.ParseUint(string(raw[i+match[2]:i+match[3]]), 0, 32)
				mask := uint64(0xffffffff)
				var maskErr error
				if match[4] >= 0 {
					mask, maskErr = strconv.ParseUint(string(raw[i+match[4]:i+match[5]]), 0, 32)
				}
				if markErr == nil && maskErr == nil {
					fmt.Fprintf(&out, `{"fw":{"mark":"0x%x","mask":"0x%x"},`, mark, mask)
					i += match[6] - 1
					continue
				}
			}
		}
		out.WriteByte(c)
	}
	return []byte(out.String())
}

func (s *Shared) checkFilters(ctx context.Context, dev, direction string, owned bool, links map[string]sharedLink) error {
	list, err := s.filters(ctx, dev, direction)
	if err != nil {
		return err
	}
	isLegacy := func(f sharedFilter) bool {
		if direction != "ingress" || f.Pref != 1 || f.Kind != "matchall" || f.Protocol != "all" || f.Chain != 0 || f.Options == nil || len(f.Options.Actions) != 2 {
			return false
		}
		first, redirect := f.Options.Actions[0], f.Options.Actions[1]
		return first.Kind == "connmark" && redirect.Kind == "mirred" && redirect.To == ifbDev && redirect.Direction == "egress" && redirect.Action == "redirect"
	}
	legacyPresent := false
	for _, f := range list {
		legacyPresent = legacyPresent || isLegacy(f)
	}
	for _, f := range list {
		// tc emits a summary before the detailed matchall filter. Recognize
		// it only alongside the complete legacy connmark+redirect action list.
		legacyHeader := legacyPresent && f.Pref == 1 && f.Kind == "matchall" && f.Protocol == "all" && f.Chain == 0 && f.Options == nil
		if isLegacy(f) || legacyHeader {
			continue
		}
		if !owned || f.Protocol != "all" || f.Chain != 0 || (f.Pref != 49150 && f.Pref != 49151) {
			return fmt.Errorf("shared shaping conflicts with existing interface filters")
		}
		if f.Pref == 49150 {
			if f.Kind != "matchall" || direction != "ingress" {
				return fmt.Errorf("shared shaping filter ownership conflict")
			}
			if f.Options != nil && (len(f.Options.Actions) != 1 || f.Options.Actions[0].Kind != "connmark") {
				return fmt.Errorf("shared shaping mark filter was changed")
			}
		}
		if f.Pref == 49151 {
			if f.Kind != "fw" {
				return fmt.Errorf("shared shaping filter ownership conflict")
			}
			if f.Options == nil {
				continue
			} // tc emits a header before the individual fw handles
			target := sharedUp
			if direction == "ingress" {
				target = ifbDev
			}
			if len(f.Options.Actions) != 1 {
				return fmt.Errorf("shared shaping redirect was changed")
			}
			_, targetExists := links[target]
			to := f.Options.Actions[0].To
			// iproute2 renders a deleted mirred target as "*". The owned
			// journal and preference identify this orphan; never accept a
			// different live target, or "*" when our target still exists.
			orphan := to == "*" && !targetExists
			if f.Options.FW == nil || f.Options.FW.Mask != "0xffffffff" {
				return fmt.Errorf("shared shaping mark selector was changed")
			}
			if f.Options.Actions[0].Kind != "mirred" || (to != target && !orphan) || f.Options.Actions[0].Direction != "egress" || f.Options.Actions[0].Action != "redirect" {
				return fmt.Errorf("shared shaping redirect was changed")
			}
		}
	}
	return nil
}
func (s *Shared) clearFilters(ctx context.Context, dev, direction string) error {
	list, err := s.filters(ctx, dev, direction)
	if err != nil {
		return err
	}
	seen := map[int]bool{}
	for _, f := range list {
		if f.Pref != 49150 && f.Pref != 49151 || seen[f.Pref] {
			continue
		}
		seen[f.Pref] = true
		if _, err := s.Root().run(ctx, "tc", "filter", "delete", "dev", dev, direction, "pref", strconv.Itoa(f.Pref)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Shared) load() ([]string, error) {
	f, err := os.OpenFile(filepath.Join(s.Dir, "shared-shaper.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !sharedOwned(st) {
		return nil, fmt.Errorf("invalid shared shaping journal")
	}
	b, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return nil, err
	}
	var list []string
	if len(b) > 8192 || json.Unmarshal(b, &list) != nil || len(list) > 256 {
		return nil, fmt.Errorf("invalid shared shaping journal")
	}
	for _, dev := range list {
		if !sharedInterface.MatchString(dev) || dev == sharedUp || dev == ifbDev || dev == "lo" {
			return nil, fmt.Errorf("invalid shared shaping interface journal")
		}
	}
	return list, nil
}
func (s *Shared) save(list []string) error {
	if err := os.MkdirAll(s.Dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(s.Dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 || !sharedOwned(st) {
		return fmt.Errorf("unsafe shared shaping state directory")
	}
	p := filepath.Join(s.Dir, "shared-shaper.json")
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("unsafe shared shaping journal")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(s.Dir, ".shared-shaper-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	b, err := json.Marshal(list)
	if err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), p); err != nil {
		return err
	}
	d, err := os.Open(s.Dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// PrimaryInterface resolves the legacy/default interface without changing it.
func (s *Shaper) PrimaryInterface(ctx context.Context) (string, error) {
	dev, err := s.iface(ctx)
	if err == nil && !sharedInterface.MatchString(strings.TrimSpace(dev)) {
		return "", fmt.Errorf("invalid shaping interface")
	}
	return dev, err
}

func sharedOwned(st os.FileInfo) bool {
	v, ok := st.Sys().(*syscall.Stat_t)
	return ok && v.Uid == uint32(os.Geteuid())
}

// Fingerprints omit counters, while retaining interface identity, marks and
// action targets. Recreated devices require fresh redirects (their ifindices
// changed), even if they kept the same names.
func (s *Shared) fingerprint(ctx context.Context, devs []string) ([32]byte, error) {
	links, err := s.links(ctx)
	if err != nil {
		return [32]byte{}, err
	}
	type state struct {
		Link    sharedLink
		In, Out []sharedFilter
	}
	states := map[string]state{}
	for _, dev := range append(append([]string(nil), devs...), sharedUp, ifbDev) {
		st := state{Link: links[dev]}
		if slices.Contains(devs, dev) {
			st.In, err = s.filters(ctx, dev, "ingress")
			if err != nil {
				return [32]byte{}, err
			}
			st.Out, err = s.filters(ctx, dev, "egress")
			if err != nil {
				return [32]byte{}, err
			}
		}
		states[dev] = st
	}
	data, err := json.Marshal(states)
	return sha256.Sum256(data), err
}

func (s *Shared) finish(ctx context.Context, devs []string, key [32]byte) error {
	if err := s.save(devs); err != nil {
		return err
	}
	state, err := s.fingerprint(ctx, devs)
	if err != nil {
		return err
	}
	s.applied, s.snapshot, s.synced = key, state, true
	return nil
}
