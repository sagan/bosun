package local

import (
	"github.com/zeptop-dev/bosun/pkg/spec"
	"testing"
)

func TestRetiredExporterSettings(t *testing.T) {
	s := openTest(t)
	// Simulate persisted settings from a version that supported exporters.
	s.st.Komari = spec.Komari{Enabled: true, Server: "https://monitor.example.com", Key: "old-secret"}
	s.st.DStatus = spec.DStatus{Enabled: true, Key: "old-secret", Listen: ":9999"}
	if got := s.KomariSettings(); got != (spec.Komari{}) {
		t.Fatal("old Komari settings exposed")
	}
	if got := s.DStatusSettings(); got != (spec.DStatus{}) {
		t.Fatal("old DStatus settings exposed")
	}
	if s.SetKomari(spec.Komari{Enabled: true}) == nil || s.SetDStatus(spec.DStatus{Enabled: true}) == nil {
		t.Fatal("retired exporter accepted")
	}
	if err := s.SetKomari(spec.Komari{}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDStatus(spec.DStatus{}); err != nil {
		t.Fatal(err)
	}
	if s.st.Komari.Key != "" || s.st.DStatus.Key != "" {
		t.Fatal("disable did not clear credentials")
	}
}
