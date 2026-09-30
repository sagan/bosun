package sysinfo

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestNVIDIAMetricsValidityAndBounds(t *testing.T) {
	data := "GPU-test-1, Test GPU, 0, 1024, 0, 42, 12.5\nGPU-test-2, Another GPU, N/A, 4096, [Not Supported], N/A, N/A\n"
	rows, truncated, err := parseNVIDIA([]byte(data))
	if err != nil || truncated || len(rows) != 2 {
		t.Fatal(rows, truncated, err)
	}
	if rows[0].Utilization == nil || *rows[0].Utilization != 0 || *rows[0].MemoryTotal != 1<<30 || *rows[0].MemoryUsed != 0 || *rows[0].Power != 12.5 {
		t.Fatal(rows[0])
	}
	if rows[1].Utilization != nil || rows[1].MemoryUsed != nil || rows[1].Temperature != nil {
		t.Fatal("unsupported became zero", rows[1])
	}
	rows, _, err = parseNVIDIA([]byte("GPU-test, GPU, 101, 1, 2, -15, Infinity\n"))
	if err != nil || rows[0].Utilization != nil || rows[0].MemoryUsed != nil || rows[0].Power != nil || *rows[0].Temperature != -15 {
		t.Fatal(rows, err)
	}
	for _, raw := range []string{"bad, csv", "N/A, GPU, 0, 1, 0, 42, 1\n", "GPU-1, GPU, 0, 1, 0, 42, 1\nGPU-1, GPU, 0, 1, 0, 42, 1\n"} {
		if _, _, err := parseNVIDIA([]byte(raw)); err == nil {
			t.Fatal("accepted invalid inventory", raw)
		}
	}
	var many strings.Builder
	for i := 0; i < 34; i++ {
		fmt.Fprintf(&many, "GPU-%d, Device, 1, 1024, 10, 42, 12\n", i)
	}
	rows, truncated, err = parseNVIDIA([]byte(many.String()))
	if err != nil || !truncated || len(rows) != 32 {
		t.Fatal(len(rows), truncated, err)
	}
	for _, raw := range []string{"NaN", "Inf", "-1", "101"} {
		if gpuNumber(raw, 1, 0, 100) != nil {
			t.Fatal(raw)
		}
	}
	if gpuBytes("NaN", 1) != nil || gpuNumber("42", math.Inf(1), 0, 100) != nil {
		t.Fatal("nonfinite metric")
	}
	var b gpuOutput
	b.Write(make([]byte, maxGPUOutput+1))
	if len(b.data) != maxGPUOutput || !b.overflow {
		t.Fatal("unbounded driver output")
	}
}

func TestAMDGPUReadOnlyFixtures(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "devices", "0000:01:00.0")
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(device, name)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("vendor", "0x1002\n")
	write("device", "0x1234")
	write("gpu_busy_percent", "0")
	write("mem_info_vram_total", "1073741824")
	write("mem_info_vram_used", "536870912")
	write("hwmon/hwmon0/name", "amdgpu")
	write("hwmon/hwmon0/temp1_input", "42500")
	write("hwmon/hwmon0/power1_average", "12500000")
	for _, card := range []string{"card0", "card1", "card0-HDMI-A-1"} {
		p := filepath.Join(root, card)
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(device, filepath.Join(p, "device")); err != nil {
			t.Fatal(err)
		}
	}
	rows, trunc, err := readAMDGPU(context.Background(), root)
	if err != nil || trunc || len(rows) != 1 {
		t.Fatal(rows, trunc, err)
	}
	if rows[0].ID != "amd:0000:01:00.0" || *rows[0].Temperature != 42.5 || *rows[0].Power != 12.5 || *rows[0].Utilization != 0 {
		t.Fatal(rows[0])
	}
	write("gpu_busy_percent", "N/A")
	write("hwmon/hwmon0/temp1_input", "invalid")
	rows, _, err = readAMDGPU(context.Background(), root)
	if err != nil || rows[0].Utilization != nil || rows[0].Temperature != nil {
		t.Fatal(rows, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = readAMDGPU(ctx, root); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func waitGPU(t *testing.T, g *gpuSampler, want string) *spec.GPUStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		v := g.snapshot()
		if v.State == want {
			return v
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state never became %s", want)
	return nil
}

func TestGPUOptionalNonBlockingCancelAndCache(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var g gpuSampler
	g.collect = func(context.Context) spec.GPUStatus {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		} // emulate a stuck driver ignoring context
		return spec.GPUStatus{State: "ok", Devices: []spec.GPUResource{{ID: "test", Name: "GPU"}}}
	}
	if g.snapshot().State != "disabled" || calls.Load() != 0 {
		t.Fatal("collected while disabled")
	}
	g.configure(true)
	if g.snapshot().State != "pending" {
		t.Fatal("first snapshot")
	}
	<-entered
	for i := 0; i < 100; i++ {
		g.snapshot()
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent collectors", calls.Load())
	}
	g.configure(false)
	if g.snapshot().State != "disabled" {
		t.Fatal("disabled state leaked")
	}
	g.configure(true)
	if g.snapshot().State != "pending" || calls.Load() != 1 {
		t.Fatal("re-enable bypassed in-flight bound")
	}
	close(release)
	v := waitGPU(t, &g, "ok")
	if calls.Load() != 2 || v.At == 0 || v.Sequence != 1 || v.Epoch == "" {
		t.Fatal("old generation published", v, calls.Load())
	}
	for i := 0; i < 100; i++ {
		if g.snapshot() != v {
			t.Fatal("cache changed")
		}
	}
	if calls.Load() != 2 {
		t.Fatal("heartbeat caused GPU work")
	}
}

func TestSamplerGPUDisableInvalidatesCachedDetail(t *testing.T) {
	var p Sampler
	p.cached = spec.SystemStatus{Resources: &spec.Resources{GPU: &spec.GPUStatus{State: "ok"}}}
	p.sampled = time.Now()
	p.Configure(&spec.ResourceOptions{GPU: false})
	s := p.Sample(context.Background())
	if s.Resources.GPU.State != "disabled" {
		t.Fatal("cached GPU leaked")
	}
	if p.cached.Resources.GPU.State != "ok" {
		t.Fatal("mutated previous shared snapshot")
	}
}

func TestGPUCommandDeadlineAndReadOnlyArguments(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux GPU command collector")
	}
	dir := t.TempDir()
	tool := filepath.Join(dir, "nvidia-smi")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(tool, []byte("#!/bin/sh\n"+body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	write(`[ "$#" -eq 2 ] || exit 1
[ "$1" = '--query-gpu=uuid,name,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw' ] || exit 1
[ "$2" = '--format=csv,noheader,nounits' ] || exit 1
printf 'GPU-fixture, Test device, 0, 1024, 0, 42, 12.5\n'
`)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v := collectGPU(ctx)
	found := false
	for _, d := range v.Devices {
		if d.ID == "nvidia:GPU-fixture" && d.Utilization != nil && *d.Utilization == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("fixed driver query did not return fixture", v.State)
	}
	write("exec sleep 10\n")
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	v = collectGPU(ctx)
	if time.Since(start) > time.Second || ctx.Err() == nil || v.State != "error" {
		t.Fatal("driver deadline not enforced", v.State, time.Since(start))
	}
}

// Opt-in read-only smoke check for the installed drivers. It never logs device
// names/IDs; fixtures remain the reproducible hardware-independent regression.
func TestGPULiveTelemetry(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("BOSUN_TEST_GPU") != "1" {
		t.Skip("set BOSUN_TEST_GPU=1 on a Linux test node")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	v := collectGPU(ctx)
	switch v.State {
	case "ok", "partial", "unavailable", "error":
	default:
		t.Fatal("invalid collector state", v.State)
	}
	if len(v.Devices) > maxGPUDevices {
		t.Fatal("unbounded inventory")
	}
	t.Logf("driver state=%s devices=%d", v.State, len(v.Devices))
}
