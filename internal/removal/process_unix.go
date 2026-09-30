//go:build linux || darwin

package removal

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const noFollow = syscall.O_NOFOLLOW

func privateOwned(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm()&0022 != 0 {
		return errors.New("removal requires root-owned paths without writable or symlink components")
	}
	return nil
}

// OpenRC stops the bosun process group. A fresh session and a distinct copied
// executable leave the worker alive to clean up and report the outcome.
func launchDetached(worker, path string) error {
	cmd := exec.Command(worker, "internal-node-removal", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
