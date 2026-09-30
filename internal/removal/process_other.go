//go:build !linux && !darwin

package removal

import "errors"

const noFollow = 0

func privateOwned(string) error           { return errors.New("unsupported platform") }
func launchDetached(string, string) error { return errors.New("unsupported platform") }
