package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

// The runtime selection survives restarts and read-only Docker config mounts.
// It overrides the installation default, never rewrites config.yaml.
type nodeModeSelection struct {
	Identity string        `json:"identity,omitempty"`
	Mode     spec.NodeMode `json:"mode"`
	Revision uint64        `json:"revision"`
}

func readNodeMode(dir string, initial spec.NodeMode) (nodeModeSelection, error) {
	p := filepath.Join(dir, "node-mode")
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nodeModeSelection{Mode: initial.Effective()}, initial.Validate()
	}
	if err != nil {
		return nodeModeSelection{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nodeModeSelection{}, err
	}
	if !st.Mode().IsRegular() {
		return nodeModeSelection{}, errors.New("node mode path must be a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nodeModeSelection{}, err
	}
	var m nodeModeSelection
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	if m.Mode == "" {
		return nodeModeSelection{}, errors.New("empty persisted node mode")
	}
	return m, m.Mode.Validate()
}

func SaveNodeMode(dir string, mode spec.NodeMode, revision uint64, identity string) error {
	if err := mode.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	p := filepath.Join(dir, "node-mode")
	if st, err := os.Lstat(p); err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("node mode path must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(dir, ".node-mode-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	b, err := json.Marshal(nodeModeSelection{Mode: mode.Effective(), Revision: revision, Identity: identity})
	if err != nil {
		f.Close()
		return err
	}
	_, err = f.Write(b)
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
	if err = os.Rename(f.Name(), p); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
