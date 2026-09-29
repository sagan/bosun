package local

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zeptop-dev/bosun/pkg/agentproto"
	"github.com/zeptop-dev/bosun/pkg/spec"
)

func TestChangeUserIDKeepsTrafficIdentity(t *testing.T) {
	s := openTest(t)
	a, err := s.CreateUser(User{Name: "alice", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	s.overDevices = map[int64]time.Time{a.ID: time.Now().Add(time.Hour)}
	if err := s.ChangeUserID(a.ID, 42); err != nil {
		t.Fatal(err)
	}
	moved, ok := s.User(42)
	if !ok || moved.UUID != a.UUID || moved.SubToken != a.SubToken || moved.Spec().ID != a.Spec().ID {
		t.Fatal("credentials changed")
	}
	if _, ok := s.overDevices[42]; !ok {
		t.Fatal("device hold lost")
	}
	b, err := s.CreateUser(User{Name: "bob", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeUserID(b.ID, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeUserID(42, a.ID); err == nil {
		t.Fatal("duplicate ID accepted")
	}
	for _, id := range []int64{0, -1, 9007199254740992} {
		if err := s.ChangeUserID(42, id); err == nil {
			t.Fatal("bad ID accepted")
		}
	}
	// Persistence and a delayed batch from before the rename.
	s, _, err = Open(s.Path(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Report(context.Background(), agentproto.Report{Traffic: []spec.UserTraffic{{UserID: a.Spec().ID, Up: 17}}}); err != nil {
		t.Fatal(err)
	}
	moved, _ = s.User(42)
	other, _ := s.User(a.ID)
	if moved.Up != 17 || other.Up != 0 {
		t.Fatal("old traffic charged a reused ID")
	}
	if err := s.DeleteUser(other.ID); err != nil {
		t.Fatal(err)
	}
	next, err := s.CreateUser(User{Name: "next", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if next.AccountingID() <= b.AccountingID() {
		t.Fatal("deleted accounting ID reused")
	}
}

func TestTrafficIdentityAfterDetach(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		t.Run(map[bool]string{false: "keep managed", true: "legacy snapshot"}[snapshot], func(t *testing.T) {
			s := openTest(t)
			if err := s.Adopt("https://panel.example.com"); err != nil {
				t.Fatal(err)
			}
			var keep *agentproto.State
			if snapshot {
				// A pre-upgrade snapshot has no explicit accounting IDs.
				s.st.Snapshot.Users = []User{{ID: 8, Name: "legacy", UUID: "legacy"}}
				raw, err := json.Marshal(s.st)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(s.Path(), raw, 0o600); err != nil {
					t.Fatal(err)
				}
				s, _, err = Open(s.Path(), slog.Default())
				if err != nil {
					t.Fatal(err)
				}
			} else {
				keep = &agentproto.State{Users: []spec.User{{ID: 8, UUID: "managed"}}}
			}
			if err := s.Detach(keep); err != nil {
				t.Fatal(err)
			}
			old := s.ListUsers()[0]
			if err := s.DeleteUser(old.ID); err != nil {
				t.Fatal(err)
			}
			next, err := s.CreateUser(User{Name: "next"})
			if err != nil {
				t.Fatal(err)
			}
			if next.AccountingID() <= old.AccountingID() {
				t.Fatal("detached accounting ID reused")
			}
		})
	}
}
