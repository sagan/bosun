package agent

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/internal/core"
	"github.com/zeptop-dev/bosun/internal/panel"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

// The sole in-flight batch is immutable. While it awaits acknowledgement,
// counters remain in the cores instead of being appended under its sequence.
// There is necessarily a small gap between resetting upstream counters and
// fsync: upstream APIs do not support transactional reads with acknowledgement.
type trafficBatch struct {
	Seq       uint64                  `json:"seq"`
	Window    int                     `json:"window"`
	Traffic   []spec.UserTraffic      `json:"traffic"`
	Inbounds  map[string]spec.Traffic `json:"inbounds,omitempty"`
	Outbounds map[string]spec.Traffic `json:"outbounds,omitempty"`
}

type trafficJournal struct {
	Version int           `json:"version"`
	Epoch   string        `json:"epoch"`
	Next    uint64        `json:"next"`
	Since   time.Time     `json:"since"`
	Pending *trafficBatch `json:"pending,omitempty"`
	path    string
}

func (a *Agent) loadTrafficJournal() error {
	if a.trafficJournal != nil {
		return nil
	}
	identity := a.driver.Name()
	if d, ok := a.driver.(interface{ TrafficIdentity() string }); ok {
		identity = d.TrafficIdentity()
		if identity == "" {
			return errors.New("traffic journal requires a paired node")
		}
	}
	dir := filepath.Join(a.cfg.DataDir, "traffic")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("traffic journal directory must be private and not a symlink")
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() {
		return errors.New("traffic journal directory owner mismatch")
	}
	path := filepath.Join(dir, fmt.Sprintf("%x.json", sha256.Sum256([]byte(identity))))
	j := &trafficJournal{Version: 1, Next: uint64(time.Now().UnixNano()), Since: a.started, path: path}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		defer f.Close()
		if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() || st.Size() > 64<<20 {
			return errors.New("invalid traffic journal file")
		}
		if err := json.NewDecoder(io.LimitReader(f, 64<<20)).Decode(j); err != nil {
			return fmt.Errorf("read traffic journal: %w", err)
		}
		if raw, err := hex.DecodeString(j.Epoch); err != nil || len(raw) != 16 || j.Version != 1 || j.Next == 0 || j.Next >= math.MaxInt64 || (j.Pending != nil && j.Pending.Seq != j.Next) {
			return errors.New("invalid traffic journal state")
		}
	} else if errors.Is(err, os.ErrNotExist) {
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		j.Epoch = hex.EncodeToString(raw)
		if err := j.save(); err != nil {
			return err
		}
	} else {
		return err
	}
	a.trafficJournal = j
	return nil
}

func (j *trafficJournal) save() error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(raw) > 64<<20 {
		return errors.New("traffic journal exceeds 64 MiB")
	}
	f, err := os.CreateTemp(filepath.Dir(j.path), ".pending-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), j.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(j.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (a *Agent) reportError(err error) bool {
	a.reportFailures.Add(1)
	a.log.Error("report deferred; traffic batch retained", "err", err)
	a.statusMu.Lock()
	a.lastReportErr = err.Error()
	a.statusMu.Unlock()
	return false
}

func (a *Agent) reportDurable(ctx context.Context, reporter panel.Reporter) bool {
	if err := a.loadTrafficJournal(); err != nil {
		return a.reportError(err)
	}
	j := a.trafficJournal
	if j.Pending == nil {
		a.pendingTraffic = map[trafficKey]*spec.UserTraffic{}
		_, traffic := a.collectUserTraffic(ctx)
		in := a.collectTagged(ctx, map[string]spec.Traffic{}, "inbound", func(c core.Core) (map[string]spec.Traffic, error) {
			if c, ok := c.(core.InboundStatser); ok {
				return c.InboundStats(ctx, true)
			}
			return nil, errSkip
		})
		out := a.collectTagged(ctx, map[string]spec.Traffic{}, "outbound", func(c core.Core) (map[string]spec.Traffic, error) {
			if c, ok := c.(core.OutboundStatser); ok {
				return c.OutboundStats(ctx, true)
			}
			return nil, errSkip
		})
		window := int(time.Since(j.Since).Seconds())
		if window < 1 {
			window = 1
		}
		j.Pending = &trafficBatch{Seq: j.Next, Window: window, Traffic: traffic, Inbounds: in, Outbounds: out}
		j.Since = time.Now()
	}
	// Always save before sending, including a retry after a failed fsync.
	if err := j.save(); err != nil {
		return a.reportError(err)
	}
	b := j.Pending
	full := a.buildReport(b.Traffic, a.SampleHost(ctx))
	full.TrafficSeq, full.TrafficEpoch, full.TrafficWindowSeconds = b.Seq, j.Epoch, b.Window
	full.Inbounds, full.Outbounds, full.Jobs = b.Inbounds, b.Outbounds, a.takeJobResults()
	changed, err := reporter.Report(ctx, full)
	if err != nil {
		a.requeueJobResults(full.Jobs)
		return a.reportError(err)
	}
	next := *j
	next.Next++
	next.Pending = nil
	if err := next.save(); err != nil {
		return a.reportError(err)
	}
	a.trafficJournal = &next
	a.lastReportOK.Store(time.Now().Unix())
	a.statusMu.Lock()
	a.lastReport, a.lastReportErr = time.Now(), ""
	if a.pendingDoctor != nil {
		a.sentDoctor, a.sentDoctorAt, a.pendingDoctor = a.pendingDoctor, time.Now(), nil
	}
	a.statusMu.Unlock()
	if ur, ok := a.driver.(panel.UpgradeRequester); ok && a.Upgrade != nil {
		if v := ur.UpgradeRequested(); v != "" && v != a.upgradeAsked {
			a.upgradeAsked = v
			go a.Upgrade(v)
		}
	}
	return changed
}
