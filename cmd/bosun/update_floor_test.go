package main

import "testing"

func TestUpdaterKeepsFirewallOwnershipCompatibilityFloor(t *testing.T) {
	for _, tc := range []struct{ configured, want string }{{"", "v0.75.0"}, {"invalid", "v0.75.0"}, {"v0.66.0", "v0.75.0"}, {"v0.72.0", "v0.75.0"}, {"v0.74.0", "v0.75.0"}, {"v0.75.0", "v0.75.0"}, {"v0.76.0", "v0.76.0"}} {
		if got := newUpdater(tc.configured).MinVersion; got != tc.want {
			t.Fatalf("floor %q: %s", tc.configured, got)
		}
	}
}
