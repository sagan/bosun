package wgsetup

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

func runCommand(ctx context.Context, name string, args ...string) error {
	path := systemTool(name)
	if path == "" {
		return errors.New("package manager unavailable")
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	cmd.WaitDelay = 2 * time.Second
	configureCommand(cmd)
	// Do not persist package output: it may contain private repository URLs.
	return cmd.Run()
}
