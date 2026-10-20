package privatecheck

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCapabilityRestrictions(t *testing.T) {
	const all = uint64(1<<6 | 1<<7 | 1<<8 | 1<<10 | 1<<12)
	status := func(e, p, b uint64) string { return fmt.Sprintf("CapEff:\t%x\nCapPrm:\t%x\nCapBnd:\t%x\n", e, p, b) }
	if !Capabilities(status(all, all, all)) {
		t.Fatal("valid permissions rejected")
	}
	for _, bit := range []uint{6, 7, 8, 12} {
		if Capabilities(status(all & ^(1<<bit), all, all)) {
			t.Fatalf("missing effective capability %d accepted", bit)
		}
	}
	for _, bit := range []uint{10, 12} {
		if Capabilities(status(all, all, all & ^(1<<bit))) {
			t.Fatalf("missing bounding capability %d accepted", bit)
		}
	}
	if Capabilities("CapEff: garbage") {
		t.Fatal("malformed status accepted")
	}
}

func TestPrerequisiteFailuresAndReadOnlyProbe(t *testing.T) {
	for _, tc := range []struct {
		uid                 int
		supported, disabled bool
		allow               int
		want                bool
	}{{1000, true, false, 0, true}, {0, true, false, 0, false}, {-1, true, false, 0, false}, {1000, false, false, 0, false}, {1000, true, true, 0, false}, {1000, true, false, 1, false}} {
		r := Check(tc.uid, tc.supported, tc.disabled, tc.allow, true)
		if r.Ready != tc.want {
			t.Fatalf("%+v: %+v", tc, r)
		}
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n[ \"$#\" = 2 ] && [ \"$1\" = list ] && [ \"$2\" = tables ]\n"
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	r := Check(1000, true, false, 0, true)
	Probe(context.Background(), r)
	if !r.Ready || len(r.Checks) != 7 {
		t.Fatalf("read-only probe failed: %+v", r)
	}
	t.Setenv("PATH", t.TempDir())
	r = Check(1000, true, false, 0, true)
	Probe(context.Background(), r)
	if r.Ready || r.Checks[6].OK {
		t.Fatal("missing nft passed")
	}
}
