package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/runas"
)

func TestPreparationPreservesMonitorConfiguration(t *testing.T) {
	runas.Clear()
	t.Cleanup(runas.Clear)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := []byte("data_dir: " + dir + "\nnode_mode: monitor\ncores:\n  user: deliberately-uncreated-account\n  egress_guard: false\n  egress_allow: [10.10.0.2]\npanel:\n  driver: local\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPreparePrivateAccess([]string{"-c", path}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(content) {
		t.Fatal("preparation changed existing configuration", err)
	}
	if runas.Active() {
		t.Fatal("monitor preparation configured an account")
	}
}
