package main

import (
	"errors"
	"time"

	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/pkg/selfupdate"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func nodeModeHook(cfg *config.Config) func(spec.NodeMode, uint64, string) error {
	return func(mode spec.NodeMode, revision uint64, identity string) error {
		if mode == spec.NodeFull && len(configuredCores(cfg)) == 0 {
			return errors.New("enable at least one core in config.yaml before switching to full mode")
		}
		if err := config.SaveNodeMode(cfg.DataDir, mode, revision, identity); err != nil {
			return err
		}
		selfupdate.Restart(time.Second)
		return nil
	}
}
