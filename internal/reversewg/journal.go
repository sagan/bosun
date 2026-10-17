package reversewg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Ownership intentionally excludes credentials and policy. A pending journal
// records every resource that a failed apply may have created, not just the
// last successfully applied desired state.
type Ownership struct {
	Slot int  `json:"slot"`
	Exit bool `json:"exit"`
}

func (o Ownership) config() Config { return Config{Slot: o.Slot, Exit: o.Exit} }
func ownership(cs []Config) []Ownership {
	out := make([]Ownership, 0, len(cs))
	for _, c := range cs {
		out = append(out, Ownership{c.Slot, c.Exit})
	}
	return out
}
func validateOwnership(rs []Ownership) error {
	if len(rs) > 128 {
		return fmt.Errorf("too many reverse WireGuard ownership records")
	}
	seen := map[int]bool{}
	for _, r := range rs {
		if r.Slot < 1 || r.Slot > 16383 || seen[r.Slot] {
			return fmt.Errorf("invalid reverse WireGuard ownership journal")
		}
		seen[r.Slot] = true
	}
	return nil
}

func readJournal(dir string) ([]Ownership, error) {
	f, err := os.OpenFile(filepath.Join(dir, "reversewg-owned.json"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
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
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || !ownedByProcess(st) {
		return nil, fmt.Errorf("reverse WireGuard journal must be a regular 0600 file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	if len(b) > 16384 {
		return nil, fmt.Errorf("reverse WireGuard journal too large")
	}
	var rs []Ownership
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, fmt.Errorf("invalid reverse WireGuard ownership journal")
	}
	return rs, validateOwnership(rs)
}

func saveJournal(dir string, rs []Ownership) error {
	if err := validateOwnership(rs); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0022 != 0 || !ownedByProcess(st) {
		return fmt.Errorf("reverse WireGuard state directory must be private and not a symlink")
	}
	p := filepath.Join(dir, "reversewg-owned.json")
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("reverse WireGuard journal must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".reversewg-owned-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	b, err := json.Marshal(rs)
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
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// FrozenFirewall is the fail-closed intermediate state of a transaction. It
// also blocks sockets bound to removed addresses, even without their routes.
func FrozenFirewall(rs []Ownership) (string, error) {
	if err := validateOwnership(rs); err != nil {
		return "", err
	}
	input, output, forward := "", "", ""
	for _, r := range rs {
		c := r.config()
		dev := c.Interface()
		input += fmt.Sprintf("iifname %q drop\n", dev)
		output += fmt.Sprintf("oifname %q drop\nip saddr %s drop\nip6 saddr %s drop\n", dev, c.Address(c.Exit, false), c.Address(c.Exit, true))
		forward += fmt.Sprintf("iifname %q drop\noifname %q drop\n", dev, dev)
	}
	return fmt.Sprintf("table inet %s {\nchain input { type filter hook input priority -10; policy accept;\n%s}\nchain output { type filter hook output priority -10; policy accept;\n%s}\nchain forward { type filter hook forward priority -10; policy accept;\n%s}\n}\n", firewallTable, input, output, forward), nil
}

func ownedByProcess(st os.FileInfo) bool {
	s, ok := st.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid())
}
