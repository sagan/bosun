package hostmanage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/zeptop-dev/bosun/pkg/spec"
)

type fileChange struct {
	Path    string
	Before  []byte
	Existed bool
	Mode    uint32
	After   []byte
	Interim []byte
	Remove  bool
}
type invocation struct {
	Name string
	Args []string
}
type transaction struct {
	ID       string
	Identity string
	Section  string
	Deadline int64
	Phase    string
	Files    []fileChange
	Do       []invocation
	Undo     []invocation
	Values   map[string]string
}
type receipt struct {
	Request string
	Result  *spec.HostResult
}
type manager struct {
	m   *machine
	dir string
}

func owned(s os.FileInfo) bool {
	st, ok := s.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

var cleanPath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

func safeDir(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("invalid management directory")
	}
	for p := path; p != "/"; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || (s.Mode().Perm()&0022 != 0 && s.Mode()&os.ModeSticky == 0) {
			return errors.New("unsafe directory permissions")
		}
		if st, ok := s.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Geteuid() && st.Uid != 0 {
			return errors.New("directory owner mismatch")
		}
	}
	return nil
}
func openManager(dataDir string) (*manager, *os.File, error) {
	if e := safeDir(dataDir); e != nil {
		return nil, nil, e
	}
	dir := filepath.Join(dataDir, "host-management")
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return nil, nil, e
	}
	if e := safeDir(dir); e != nil {
		return nil, nil, e
	}
	fd, e := syscall.Open(filepath.Join(dir, "lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, nil, e
	}
	f := os.NewFile(uintptr(fd), "lock")
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, nil, errors.New("host management is busy")
	}
	return &manager{m: realMachine(), dir: dir}, f, nil
}
func atomic(path string, b []byte, mode os.FileMode) error {
	// Never follow a destination symlink. The parent of every write is trusted.
	if s, e := os.Lstat(path); e == nil && (!s.Mode().IsRegular() || s.Mode()&os.ModeSymlink != 0 || !owned(s)) {
		return errors.New("unsafe destination")
	}
	if e := safeDir(filepath.Dir(path)); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".host-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (g *manager) save(name string, v any) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomic(filepath.Join(g.dir, name), b, 0600)
}
func (g *manager) load(name string, v any) error {
	path := filepath.Join(g.dir, name)
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() || s.Mode().Perm()&0077 != 0 || !owned(s) {
		return errors.New("unsafe management journal")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 2<<20)).Decode(v)
}
func (g *manager) pending() *transaction {
	var t transaction
	if e := g.load("pending.json", &t); e != nil {
		if !os.IsNotExist(e) {
			return &transaction{Phase: "journal_invalid"}
		}
		return nil
	}
	if t.Phase != "complete" && t.Phase != "restored" {
		return &t
	}
	return nil
}
func (g *manager) snapshot(ctx context.Context) *spec.HostSnapshot {
	s := g.m.inspect(ctx)
	if t := g.pending(); t != nil {
		s.Pending = &spec.HostPending{ID: t.ID, Section: t.Section, Deadline: t.Deadline, Phase: t.Phase}
	}
	return s
}
func (g *manager) capture(t *transaction) error {
	for i := range t.Files {
		f := &t.Files[i]
		path := g.m.path(f.Path)
		if e := safeDir(filepath.Dir(path)); e != nil {
			return e
		}
		s, e := os.Lstat(path)
		if os.IsNotExist(e) {
			if f.Mode == 0 {
				f.Mode = 0644
			}
			continue
		}
		if e != nil {
			return e
		}
		if !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 || !owned(s) {
			return errors.New("unsafe configuration file")
		}
		f.Mode = uint32(s.Mode().Perm())
		f.Before, e = readLimited(path)
		if e != nil {
			return e
		}
		f.Existed = true
	}
	return nil
}
func (g *manager) writeFiles(t *transaction, restore bool) error {
	for _, f := range t.Files {
		path := g.m.path(f.Path)
		b := f.After
		remove := f.Remove
		mode := os.FileMode(f.Mode)
		if restore {
			b = f.Before
			remove = !f.Existed
		}
		if remove {
			if e := safeDir(filepath.Dir(path)); e != nil {
				return e
			}
			s, e := os.Lstat(path)
			if e != nil && !os.IsNotExist(e) {
				return e
			}
			if e == nil {
				if !s.Mode().IsRegular() {
					return errors.New("unsafe configuration file")
				}
				if e = os.Remove(path); e != nil {
					return e
				}
			}
		} else if e := atomic(path, b, mode); e != nil {
			return e
		}
	}
	return nil
}
func (g *manager) commands(ctx context.Context, cmds []invocation) error {
	for _, c := range cmds {
		if _, e := g.m.run(ctx, c.Name, c.Args...); e != nil {
			return fmt.Errorf("%s operation failed", c.Name)
		}
	}
	return nil
}
func (g *manager) restore(ctx context.Context, t *transaction) error {
	if t.Phase == "journal_invalid" {
		return errors.New("host journal is invalid; manual recovery required")
	}
	t.Phase = "restoring"
	if e := g.save("pending.json", t); e != nil {
		return e
	}
	// Refuse to overwrite a third-party edit made after this transaction.
	for _, f := range t.Files {
		current, e := readLimited(g.m.path(f.Path))
		if os.IsNotExist(e) && (!f.Existed || f.Remove) {
			continue
		}
		if e != nil || (!bytes.Equal(current, f.Before) && !bytes.Equal(current, f.After) && (f.Interim == nil || !bytes.Equal(current, f.Interim))) {
			t.Phase = "recovery_failed"
			_ = g.save("pending.json", t)
			return errors.New("configuration changed outside this transaction; manual recovery required")
		}
	}
	err := g.writeFiles(t, true)
	if t.Section == "swap" {
		path := "/var/lib/bosun-host.swap"
		if strings.Contains(g.m.read("/proc/swaps"), path) {
			if _, e := g.m.run(ctx, "swapoff", path); e != nil {
				err = errors.Join(err, errors.New("could not deactivate managed swap"))
			}
		}
		if err == nil {
			if e := os.Remove(g.m.path(path)); e != nil && !os.IsNotExist(e) {
				err = e
			}
		}
	}
	if e := g.commands(ctx, t.Undo); e != nil {
		err = errors.Join(err, e)
	}
	if err != nil {
		t.Phase = "recovery_failed"
		_ = g.save("pending.json", t)
		return errors.New("recovery could not be verified; retained transaction for retry")
	}
	t.Phase = "restored"
	return g.save("pending.json", t)
}
func (g *manager) installRecovery(ctx context.Context) error {
	exe, e := os.Executable()
	if e != nil {
		return e
	}
	exe, e = filepath.EvalSymlinks(exe)
	if e != nil || !cleanPath.MatchString(exe) || !cleanPath.MatchString(filepath.Dir(g.dir)) {
		return errors.New("unsupported recovery executable or data path")
	}
	unit := "[Unit]\nDescription=Bosun pending host change recovery\nAfter=local-fs.target\n[Service]\nType=oneshot\nExecStart=" + exe + " internal-host-recover " + filepath.Dir(g.dir) + "\n"
	timer := "[Unit]\nDescription=Check Bosun host recovery deadlines\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=30s\nAccuracySec=1s\n[Install]\nWantedBy=timers.target\n"
	for name, body := range map[string]string{"bosun-host-recovery.service": unit, "bosun-host-recovery.timer": timer} {
		path := g.m.path("/etc/systemd/system/" + name)
		old, e := os.ReadFile(path)
		if e == nil && (!strings.Contains(string(old), "Bosun") || (name == "bosun-host-recovery.service" && !strings.Contains(string(old), " internal-host-recover "+filepath.Dir(g.dir)+"\n"))) {
			return errors.New("recovery unit name already owned")
		}
		if e = atomic(path, []byte(body), 0644); e != nil {
			return e
		}
	}
	if e = g.commands(ctx, []invocation{{"systemctl", []string{"daemon-reload"}}, {"systemctl", []string{"enable", "--now", "bosun-host-recovery.timer"}}}); e != nil {
		return e
	}
	if !g.m.active(ctx, "bosun-host-recovery.timer") {
		return errors.New("recovery timer did not start")
	}
	return nil
}

// Recover runs under a separate persistent systemd timer, independent of the
// Captain connection and of bosun's service restart. It is also retried after
// a failed restore. A restored journal is kept for inspection, not replayed.
func Recover(ctx context.Context, dataDir string) error {
	g, lock, e := openManager(dataDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	t := g.pending()
	if t == nil || time.Now().Unix() < t.Deadline {
		return nil
	}
	return g.restore(ctx, t)
}
func Run(ctx context.Context, dataDir, identity, job string, r spec.HostRequest) spec.HostResult {
	if e := r.Validate(); e != nil {
		return spec.HostResult{Outcome: "invalid", Message: e.Error()}
	}
	// Inspect never modifies host configuration. A writable data directory permits
	// reading pending state under the same interprocess lock as mutations.
	if r.Action == "inspect" {
		// Never hold the recovery lock across observation subprocesses. A slow
		// systemctl query must not starve an expired local recovery deadline.
		state := realMachine().inspect(ctx)
		g, lock, e := openManager(dataDir)
		if e == nil {
			if t := g.pending(); t != nil {
				state.Pending = &spec.HostPending{ID: t.ID, Section: t.Section, Deadline: t.Deadline, Phase: t.Phase}
			}
			lock.Close()
			return spec.HostResult{Outcome: "ok", State: state}
		}
		for i := range state.Items {
			state.Items[i].Editable = false
			state.Items[i].Reason = "host_busy_or_storage"
		}
		return spec.HostResult{Outcome: "unavailable", State: state, Message: "host journal is busy or unavailable; retry inspection"}
	}

	g, lock, e := openManager(dataDir)
	if e != nil {
		return spec.HostResult{Outcome: "failed", Message: e.Error()}
	}
	defer lock.Close()
	if !g.m.supported(ctx) {
		return spec.HostResult{Outcome: "unsupported", State: g.snapshot(ctx), Message: "host writes require native root Debian/Ubuntu with systemd"}
	}
	return g.perform(ctx, identity, job, r)
}
func (g *manager) perform(ctx context.Context, identity, job string, r spec.HostRequest) spec.HostResult {
	raw, _ := json.Marshal(r)
	request := digest(string(raw))
	key := digest(identity + "\x00" + job)
	file := "receipt-" + key + ".json"
	var previous receipt
	e := g.load(file, &previous)
	if e == nil {
		if previous.Request != request {
			return spec.HostResult{Outcome: "invalid", Message: "job identity mismatch"}
		}
		if previous.Result != nil {
			return *previous.Result
		}
		return spec.HostResult{Outcome: "unknown", State: g.snapshot(ctx), Message: "previous execution interrupted; inspect pending recovery before retry"}
	}
	if !os.IsNotExist(e) {
		return spec.HostResult{Outcome: "unknown", Message: "existing operation receipt is unreadable; refusing to replay"}
	}
	if identity == "" || job == "" {
		return spec.HostResult{Outcome: "invalid", Message: "panel and task identities required"}
	}
	if e = g.save(file, receipt{Request: request}); e != nil {
		return spec.HostResult{Outcome: "failed", Message: "cannot persist operation receipt"}
	}
	result := g.execute(ctx, identity, key, r)
	result.State = g.snapshot(ctx)
	if e = g.save(file, receipt{Request: request, Result: &result}); e != nil {
		result.Outcome = "unknown"
		result.Message = "operation receipt could not be saved; inspect actual state"
	}
	return result
}
func (g *manager) execute(ctx context.Context, identity, id string, r spec.HostRequest) spec.HostResult {
	fail := func(e error) spec.HostResult { return spec.HostResult{Outcome: "failed", Message: e.Error()} }
	pending := g.pending()
	if r.Action == "confirm" || r.Action == "rollback" {
		if pending == nil || pending.ID != r.Transaction || pending.Identity != digest(identity) {
			return fail(errors.New("pending transaction does not match current panel identity"))
		}
		if r.Action == "rollback" {
			if e := g.restore(ctx, pending); e != nil {
				return fail(e)
			}
			return spec.HostResult{Outcome: "restored"}
		}
		if time.Now().Unix() >= pending.Deadline {
			return fail(errors.New("confirmation deadline expired; restore instead"))
		}
		if pending.Phase != "waiting" {
			return fail(errors.New("transaction is not awaiting confirmation"))
		}
		for _, f := range pending.Files {
			b, e := readLimited(g.m.path(f.Path))
			if e != nil || !bytes.Equal(b, f.After) {
				return fail(errors.New("configuration changed after apply; inspect and restore before confirming"))
			}
		}
		if e := g.finalize(ctx, pending); e != nil {
			return fail(e)
		}
		pending.Phase = "complete"
		if e := g.save("pending.json", pending); e != nil {
			return fail(e)
		}
		return spec.HostResult{Outcome: "complete"}
	}
	if pending != nil {
		return fail(errors.New("complete or restore the pending host change first"))
	}
	s := g.m.inspect(ctx)
	if s.Revision != r.Revision {
		return fail(errors.New("host configuration changed; refresh and review again"))
	}
	allowed := false
	for _, item := range s.Items {
		if item.ID == r.Section {
			allowed = item.Editable
		}
	}
	if !allowed {
		return fail(errors.New("operation unavailable for current host configuration"))
	}
	t, e := g.plan(ctx, r)
	if e != nil {
		return fail(e)
	}
	t.ID = id
	t.Identity = digest(identity)
	t.Deadline = time.Now().Add(10 * time.Minute).Unix()
	t.Phase = "applying"
	if e = g.capture(t); e != nil {
		return fail(e)
	}
	if current := g.m.inspect(ctx); current.Revision != r.Revision {
		return fail(errors.New("host changed during preparation; refresh and review again"))
	}
	if e = g.installRecovery(ctx); e != nil {
		return fail(e)
	}
	if e = g.save("pending.json", t); e != nil {
		return fail(e)
	}
	if t.Section == "swap" {
		path := g.m.path("/var/lib/bosun-host.swap")
		fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_NOFOLLOW, 0600)
		if err != nil {
			t.Phase = "restored"
			_ = g.save("pending.json", t)
			return fail(errors.New("cannot reserve managed swap file"))
		}
		syscall.Close(fd)
	}
	if e = g.writeFiles(t, false); e == nil {
		e = g.commands(ctx, t.Do)
	}
	if t.Section == "firewall" {
		for i := range t.Files {
			if b, readErr := readLimited(g.m.path(t.Files[i].Path)); readErr == nil {
				t.Files[i].After = b
			}
		}
		if saveErr := g.save("pending.json", t); saveErr != nil {
			return fail(errors.New("cannot persist applied firewall state; inspect local recovery journal"))
		}
	}
	if e == nil {
		e = g.verify(ctx, t)
	}
	if e != nil {
		re := g.restore(context.WithoutCancel(ctx), t)
		if re != nil {
			return fail(errors.Join(e, re))
		}
		return fail(fmt.Errorf("%s; original settings restored", e))
	}
	if r.Section == "ssh" || r.Section == "port" || r.Section == "admin" || r.Section == "dns" || r.Section == "firewall" {
		t.Phase = "waiting"
	} else {
		t.Phase = "complete"
	}
	if e = g.save("pending.json", t); e != nil {
		return fail(errors.New("change applied but journal update failed; local recovery remains armed"))
	}
	return spec.HostResult{Outcome: t.Phase}
}

// CanRemove prevents deleting the recovery executable/data while access changes
// are awaiting confirmation. Permanent host settings are not undone on removal.
func CanRemove(dataDir string) error {
	if _, e := os.Lstat(filepath.Join(dataDir, "host-management")); os.IsNotExist(e) {
		return nil
	}
	g, lock, e := openManager(dataDir)
	if e != nil {
		return e
	}
	defer lock.Close()
	if g.pending() != nil {
		return errors.New("complete or restore pending host management before removing bosun")
	}
	return nil
}
func Cleanup(ctx context.Context, dataDir string) error {
	if e := CanRemove(dataDir); e != nil {
		return e
	}
	service := "/etc/systemd/system/bosun-host-recovery.service"
	b, e := readLimited(service)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !strings.Contains(string(b), " internal-host-recover "+dataDir+"\n") {
		return errors.New("host recovery service belongs to another data directory")
	}
	for _, args := range [][]string{{"disable", "--now", "bosun-host-recovery.timer"}, {"stop", "bosun-host-recovery.service"}} {
		if _, e := command(ctx, "systemctl", args...); e != nil {
			return e
		}
	}
	for _, p := range []string{service, "/etc/systemd/system/bosun-host-recovery.timer"} {
		st, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() {
			return errors.New("unsafe recovery unit")
		}
		if e = os.Remove(p); e != nil {
			return e
		}
	}
	_, e = command(ctx, "systemctl", "daemon-reload")
	return e
}
