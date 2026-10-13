package spec

import "testing"

func TestPublicLabel(t *testing.T) {
	for _, ok := range []string{"", "Tokyo 01", "日本-东京 (IPLC)", "cf 1.1.1.1:443", "HK | CMI"} {
		if !PublicLabel(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"<img src=x onerror=alert(1)>", "a\"b", "a'b", "x&y", "tab\there", "nl\n", "`tick`"} {
		if PublicLabel(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if err := (PingTask{Name: "<b>cf</b>", Type: "tcp", Target: "192.0.2.10:443"}).Validate(); err == nil {
		t.Fatal("ping task name with markup accepted")
	}
}
