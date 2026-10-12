package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestNodeModePersistenceAndLegacyDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: "+dir+"\nnode_mode: monitor\ncores:\n  xray: {}\npanel:\n  driver: local\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil || c.NodeMode != spec.NodeMonitor || c.MinVersion != spec.NodeModeMinVersion {
		t.Fatal(c, err)
	}
	if err = SaveNodeMode(dir, spec.NodeFull, 2, "test-identity"); err != nil {
		t.Fatal(err)
	}
	c, err = Load(path)
	if err != nil || c.NodeMode != spec.NodeFull || c.MinVersion != spec.NodeModeMinVersion || c.NodeModeRevision != 2 || c.NodeModeIdentity != "test-identity" {
		t.Fatal(c, err)
	}
	if err = SaveNodeMode(dir, "typo", 2, "test-identity"); err == nil {
		t.Fatal("invalid mode persisted")
	}
	if err = os.WriteFile(filepath.Join(dir, "node-mode"), []byte("typo"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("corrupt state defaulted to full")
	}
	os.Remove(filepath.Join(dir, "node-mode"))
	os.Symlink(path, filepath.Join(dir, "node-mode"))
	if _, err = Load(path); err == nil {
		t.Fatal("followed symlink")
	}
	if err = SaveNodeMode(dir, spec.NodeFull, 2, "test-identity"); err == nil {
		t.Fatal("replaced symlink")
	}
	if m, err := readNodeMode(t.TempDir(), ""); err != nil || m.Mode != spec.NodeFull {
		t.Fatal(m, err)
	}
}
