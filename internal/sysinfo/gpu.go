package sysinfo

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

const gpuInterval = 15 * time.Second
const maxGPUDevices = 32
const maxGPUOutput = 64 << 10

// At most one collector can be in flight even across disable/re-enable. Sysfs
// drivers may block in the kernel; they must never block the host sample lock or
// cause an accumulating goroutine per heartbeat. Published snapshots are immutable.
type gpuSampler struct {
	mu               sync.Mutex
	enabled, running bool
	generation       uint64
	epoch            string
	sequence         uint64
	attempted        time.Time
	value            *spec.GPUStatus
	cancel           context.CancelFunc
	collect          func(context.Context) spec.GPUStatus // fixed local collector; tests may replace
}

func (g *gpuSampler) configure(enabled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if enabled == g.enabled {
		return
	}
	g.enabled = enabled
	g.generation++
	g.value = nil
	g.attempted = time.Time{}
	if g.cancel != nil {
		g.cancel()
	}
}

func (g *gpuSampler) snapshot() *spec.GPUStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.enabled {
		return &spec.GPUStatus{State: "disabled"}
	}
	if !g.running && (g.attempted.IsZero() || time.Since(g.attempted) >= gpuInterval) {
		g.running, g.attempted = true, time.Now()
		if g.epoch == "" {
			g.epoch = rand.Text()
		}
		generation := g.generation
		collect := g.collect
		if collect == nil {
			collect = collectGPU
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		g.cancel = cancel
		go func() {
			defer cancel()
			result := collect(ctx)
			if ctx.Err() != nil {
				result = spec.GPUStatus{State: "error"}
			}
			result.At = time.Now().UnixMilli()
			g.mu.Lock()
			defer g.mu.Unlock()
			g.running, g.cancel = false, nil
			if !g.enabled || g.generation != generation {
				return
			}
			g.sequence++
			result.Epoch, result.Sequence = g.epoch, g.sequence
			g.value = &result
		}()
	}
	if g.value == nil {
		return &spec.GPUStatus{State: "pending"}
	}
	return g.value
}

func collectGPU(ctx context.Context) spec.GPUStatus {
	if runtime.GOOS != "linux" {
		return spec.GPUStatus{State: "unsupported"}
	}
	out := spec.GPUStatus{State: "unavailable", Devices: []spec.GPUResource{}}
	failed := false
	if path, err := exec.LookPath("nvidia-smi"); err == nil {
		cmd := exec.CommandContext(ctx, path, "--query-gpu=uuid,name,utilization.gpu,memory.total,memory.used,temperature.gpu,power.draw", "--format=csv,noheader,nounits")
		cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
		cmd.WaitDelay = 100 * time.Millisecond
		buf := &gpuOutput{}
		cmd.Stdout, cmd.Stderr = buf, io.Discard
		if err := cmd.Run(); err != nil || buf.overflow {
			failed = true
		} else {
			devices, truncated, err := parseNVIDIA(buf.data)
			failed = err != nil
			out.Devices, out.Truncated = devices, truncated
		}
	}
	amd, truncated, err := readAMDGPU(ctx, "/sys/class/drm")
	failed = failed || err != nil
	out.Truncated = out.Truncated || truncated
	out.Devices = append(out.Devices, amd...)
	sort.Slice(out.Devices, func(i, j int) bool { return out.Devices[i].ID < out.Devices[j].ID })
	if len(out.Devices) > maxGPUDevices {
		out.Devices = out.Devices[:maxGPUDevices]
		out.Truncated = true
	}
	if len(out.Devices) > 0 {
		out.State = "ok"
	}
	if failed {
		out.State = "error"
		if len(out.Devices) > 0 {
			out.State = "partial"
		}
	}
	return out
}

type gpuOutput struct {
	data     []byte
	overflow bool
}

func (b *gpuOutput) Write(p []byte) (int, error) {
	n := min(len(p), maxGPUOutput-len(b.data))
	b.data = append(b.data, p[:n]...)
	b.overflow = b.overflow || n < len(p)
	return len(p), nil
}
func gpuNumber(raw string, scale, minValue, maxValue float64) *float64 {
	x, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	x *= scale
	if err != nil || math.IsNaN(x) || math.IsInf(x, 0) || x < minValue || x > maxValue {
		return nil
	}
	return &x
}
func gpuBytes(raw string, scale float64) *uint64 {
	x := gpuNumber(raw, scale, 0, 1<<50)
	if x == nil {
		return nil
	}
	v := uint64(*x)
	return &v
}
func cleanGPUText(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 128 || !spec.Plain(s) {
		return ""
	}
	return s
}

func parseNVIDIA(raw []byte) ([]spec.GPUResource, bool, error) {
	r := csv.NewReader(strings.NewReader(string(raw)))
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = 7
	out := []spec.GPUResource{}
	seen := map[string]bool{}
	for {
		row, err := r.Read()
		if errors.Is(err, io.EOF) {
			return out, false, nil
		}
		if err != nil {
			return out, false, err
		}
		if len(out) == maxGPUDevices {
			return out, true, nil
		}
		id, name := cleanGPUText(row[0]), cleanGPUText(row[1])
		if !strings.HasPrefix(id, "GPU-") || seen[id] || name == "" {
			return out, false, errors.New("invalid GPU identity")
		}
		seen[id] = true
		v := spec.GPUResource{ID: "nvidia:" + id, Name: name, Vendor: "nvidia", Utilization: gpuNumber(row[2], 1, 0, 100), MemoryTotal: gpuBytes(row[3], 1<<20), MemoryUsed: gpuBytes(row[4], 1<<20), Temperature: gpuNumber(row[5], 1, -100, 250), Power: gpuNumber(row[6], 1, 0, 10000)}
		if v.MemoryUsed != nil && v.MemoryTotal != nil && *v.MemoryUsed > *v.MemoryTotal {
			v.MemoryUsed = nil
		}
		out = append(out, v)
	}
}

func gpuFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// The amdgpu driver's documented read-only sysfs/hwmon attributes. No ROCm
// dependency, PCI database download, process list, or writable control access.
func readAMDGPU(ctx context.Context, root string) ([]spec.GPUResource, bool, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	out := []spec.GPUResource{}
	seen := map[string]bool{}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return out, false, ctx.Err()
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "card") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(name, "card")); err != nil {
			continue
		}
		device := filepath.Join(root, name, "device")
		if gpuFile(filepath.Join(device, "vendor")) != "0x1002" {
			continue
		}
		resolved, err := filepath.EvalSymlinks(device)
		if err != nil {
			continue
		}
		if seen[resolved] {
			continue
		}
		seen[resolved] = true
		if len(out) == maxGPUDevices {
			return out, true, nil
		}
		id := "amd:" + filepath.Base(resolved)
		model := cleanGPUText(gpuFile(filepath.Join(device, "product_name")))
		if model == "" {
			model = "AMD " + cleanGPUText(gpuFile(filepath.Join(device, "device")))
		}
		v := spec.GPUResource{ID: id, Name: model, Vendor: "amd", Utilization: gpuNumber(gpuFile(filepath.Join(device, "gpu_busy_percent")), 1, 0, 100), MemoryTotal: gpuBytes(gpuFile(filepath.Join(device, "mem_info_vram_total")), 1), MemoryUsed: gpuBytes(gpuFile(filepath.Join(device, "mem_info_vram_used")), 1)}
		if v.MemoryUsed != nil && v.MemoryTotal != nil && *v.MemoryUsed > *v.MemoryTotal {
			v.MemoryUsed = nil
		}
		monitors, _ := filepath.Glob(filepath.Join(device, "hwmon", "hwmon*"))
		for _, hw := range monitors {
			if ctx.Err() != nil {
				return out, false, ctx.Err()
			}
			if gpuFile(filepath.Join(hw, "name")) != "amdgpu" {
				continue
			}
			v.Temperature = gpuNumber(gpuFile(filepath.Join(hw, "temp1_input")), .001, -100, 250)
			v.Power = gpuNumber(gpuFile(filepath.Join(hw, "power1_average")), .000001, 0, 10000)
			if v.Power == nil {
				v.Power = gpuNumber(gpuFile(filepath.Join(hw, "power1_input")), .000001, 0, 10000)
			}
			break
		}
		out = append(out, v)
	}
	return out, false, nil
}
