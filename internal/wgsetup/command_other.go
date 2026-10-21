//go:build !linux

package wgsetup

import "os/exec"

func configureCommand(cmd *exec.Cmd) {}
