package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/zeptop-dev/bosun/internal/config"
)

func TestManagedRuntimeParentsTraversable(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "repair"}[existing], func(t *testing.T) {
			cfg := &config.Config{DataDir: t.TempDir()}
			if err := os.Chmod(cfg.DataDir, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(cfg.DataDir, "core-runtime", "xray", "26.3.27-r1")
			if existing {
				if err := os.MkdirAll(dir, 0750); err != nil {
					t.Fatal(err)
				}
			}
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := managedFactory(cfg, slog.Default(), nil)("xray", binary, dir); err != nil {
				t.Fatal(err)
			}
			for path := dir; path != cfg.DataDir; path = filepath.Dir(path) {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if mode := info.Mode().Perm(); mode&0001 == 0 || mode&0022 != 0 {
					t.Errorf("core account cannot safely traverse %s (mode %04o)", path, mode)
				}
			}
			info, err := os.Stat(cfg.DataDir)
			if err != nil || info.Mode().Perm() != 0700 {
				t.Fatal("factory changed data directory permissions", info, err)
			}
		})
	}
}

func TestManagedRuntimeRefusesOutsideAndSymlink(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Chmod(outside, 0700); err != nil {
		t.Fatal(err)
	}
	if err := prepareManagedWorkDir(root, outside); err == nil {
		t.Fatal("accepted an outside directory")
	}
	link := filepath.Join(root, "core-runtime")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareManagedWorkDir(root, filepath.Join(link, "xray", "version")); err == nil {
		t.Fatal("followed a managed-directory symlink")
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0700 {
		t.Fatal("changed outside directory permissions", info, err)
	}
}
