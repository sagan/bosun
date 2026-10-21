package wgfirewall

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

type entry struct {
	Rule  Rule   `json:"rule"`
	Token string `json:"token"`
}

func (e entry) marker() string { return "bosun-wg-" + e.Token }

type journal struct {
	Version int              `json:"version"`
	Entries map[string]entry `json:"entries"`
}

var tokenPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)

func (m *Manager) load() error {
	if m.loaded {
		return nil
	}
	if m.StateFile == "" {
		return errors.New("persistent_forwarding_state_required")
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(m.StateFile))
	if err != nil {
		return errors.New("forwarding_state_directory_unavailable")
	}
	m.StateFile = filepath.Join(dir, filepath.Base(m.StateFile))
	if err := safeDirectory(dir); err != nil {
		return err
	}
	m.data = journal{Version: 1, Entries: map[string]entry{}}
	st, err := os.Lstat(m.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		m.loaded = true
		return nil
	}
	if err != nil {
		return errors.New("forwarding_state_unreadable")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 8<<20 || !ok || int(owner.Uid) != os.Geteuid() {
		return errors.New("forwarding_state_unsafe")
	}
	fd, err := syscall.Open(m.StateFile, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("forwarding_state_unreadable")
	}
	f := os.NewFile(uintptr(fd), m.StateFile)
	b, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	f.Close()
	if err != nil || len(b) > 8<<20 || json.Unmarshal(b, &m.data) != nil {
		return errors.New("forwarding_state_invalid")
	}
	if m.data.Version != 1 || m.data.Entries == nil {
		return errors.New("forwarding_state_version_unsupported")
	}
	for k, e := range m.data.Entries {
		if k != e.Rule.key() || !e.Rule.valid() || !tokenPattern.MatchString(e.Token) {
			return errors.New("forwarding_ownership_invalid")
		}
	}
	m.loaded = true
	return nil
}

// An intent is durable before a command can create its corresponding rule.
// A crash between the command and its observation therefore preserves proof
// of ownership without adopting a rule based only on its traffic selectors.
func (m *Manager) save() error {
	dir := filepath.Dir(m.StateFile)
	if err := safeDirectory(dir); err != nil {
		return err
	}
	if st, err := os.Lstat(m.StateFile); err == nil && !st.Mode().IsRegular() {
		return errors.New("forwarding_state_unsafe")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("forwarding_state_unreadable")
	}
	b, err := json.Marshal(m.data)
	if err != nil {
		return errors.New("forwarding_state_encoding_failed")
	}
	f, err := os.CreateTemp(dir, ".wg-firewall-*")
	if err != nil {
		return errors.New("forwarding_state_write_failed")
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("forwarding_state_sync_failed")
	}
	if os.Rename(f.Name(), m.StateFile) != nil {
		return errors.New("forwarding_state_replace_failed")
	}
	d, err := os.Open(dir)
	if err != nil {
		return errors.New("forwarding_state_directory_unavailable")
	}
	defer d.Close()
	if d.Sync() != nil {
		return errors.New("forwarding_state_directory_sync_failed")
	}
	return nil
}

func safeDirectory(dir string) error {
	for p := dir; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return errors.New("forwarding_state_directory_unavailable")
		}
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || (st.Mode().Perm()&0022 != 0 && st.Mode()&os.ModeSticky == 0) || !ok || (int(owner.Uid) != os.Geteuid() && owner.Uid != 0) {
			return errors.New("forwarding_state_directory_unsafe")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
