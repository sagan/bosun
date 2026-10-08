package agent

import (
	"context"
	"github.com/zeptop-dev/bosun/internal/config"
	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/egressguard"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestDisabledEgressReconcilesBeforeOfflineBootstrap(t *testing.T) {
	a := New(&config.Config{}, nopDriver{}, core.NewRegistry(), nil, slog.Default())
	a.EgressDisabled = true
	a.EgressProtectedPorts = []int{9101}
	var applied string
	a.Egress = &egressguard.Guard{Run: func(_ context.Context, stdin, name string, args ...string) ([]byte, error) {
		applied = stdin
		return nil, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := a.Run(ctx); err == nil {
		t.Fatal("offline bootstrap should time out")
	}
	if !strings.Contains(applied, "delete table inet bosun_egress") || !strings.Contains(applied, "skuid != 0") || strings.Contains(applied, "ct state new") {
		t.Fatal("disabled policy waited for Captain or lost API guard", applied)
	}
}
