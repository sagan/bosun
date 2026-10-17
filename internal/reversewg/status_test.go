package reversewg

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStatusFreshnessAndRotation(t *testing.T) {
	a, _ := pair(t)
	now := time.Unix(1000, 0)
	for _, tc := range []struct {
		stamp     int
		connected bool
	}{{0, false}, {819, false}, {820, true}, {1000, true}, {1001, false}} {
		st, err := ParseStatus(a, fmt.Sprintf("%s\t%d\n", a.PeerKey, tc.stamp), a.PeerKey+"\t123\t456\n", now)
		if err != nil || st.Connected != tc.connected || st.Receive != 123 || st.Transmit != 456 {
			t.Fatalf("timestamp %d: status=%+v err=%v", tc.stamp, st, err)
		}
	}
	for _, raw := range []string{"", a.PeerKey + " -1", a.PeerKey + " 1000\n" + a.PeerKey + " 1000", "different-peer 1000"} {
		if _, err := ParseStatus(a, raw, a.PeerKey+" 1 2", now); err == nil {
			t.Fatal("accepted invalid handshake")
		}
	}
	for _, raw := range []string{a.PeerKey + " -1 2", a.PeerKey + " 18446744073709551616 2", a.PrivateKey + " 1 2"} {
		_, err := ParseStatus(a, a.PeerKey+" 1000", raw, now)
		if err == nil {
			t.Fatal("accepted invalid counters")
		}
		if strings.Contains(err.Error(), a.PrivateKey) {
			t.Fatal("error exposes key")
		}
	}
}
