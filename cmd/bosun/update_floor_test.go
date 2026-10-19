package main

import "testing"

func TestUpdaterKeepsFirewallOwnershipCompatibilityFloor(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{{"", "v0.72.0"}, {"invalid", "v0.72.0"}, {"v0.66.0", "v0.72.0"}, {"v0.70.0", "v0.72.0"}, {"v0.71.0", "v0.72.0"}, {"v0.73.0", "v0.73.0"}} {
		if got := newUpdater(tc.configured).MinVersion; got != tc.want {
			t.Fatalf("floor %q: %s", tc.configured, got)
		}
	}
}
