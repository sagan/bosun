package main

import "testing"

func TestUpdaterKeepsWireGuardCompatibilityFloor(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{{"", "v0.68.0"}, {"invalid", "v0.68.0"}, {"v0.66.0", "v0.68.0"}, {"v0.70.0", "v0.70.0"}} {
		if got := newUpdater(tc.configured).MinVersion; got != tc.want {
			t.Fatalf("floor %q: %s", tc.configured, got)
		}
	}
}
