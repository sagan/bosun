package spec

import "testing"

func TestIngressPortMappings(t *testing.T) {
	p := IngressPorts{Mappings: []PortMapping{{20000, 20009, 30000}, {40000, 40000, 443}}, Reserved: []int{20000}}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		local, public int
		allowed       bool
	}{{20000, 30000, false}, {20001, 30001, true}, {20009, 30009, true}, {20010, 0, false}, {40000, 443, true}, {0, 0, false}, {65536, 0, false}} {
		if p.EntryPort(tc.local) != tc.public || (p.Check(tc.local) == nil) != tc.allowed {
			t.Fatalf("port %d: mapping=%d err=%v", tc.local, p.EntryPort(tc.local), p.Check(tc.local))
		}
	}
	for _, bad := range []IngressPorts{
		{From: 1}, {From: 20, To: 10}, {From: 1, To: 10, Offset: -1}, {From: 65530, To: 65535, Offset: 1}, {Reserved: []int{0}}, {Reserved: []int{65536}},
		{Offset: int(^uint(0) >> 1)}, {Mappings: []PortMapping{{1, 2, 65535}}}, {Mappings: []PortMapping{{2, 1, 1}}}, {Mappings: []PortMapping{{0, 2, 1}}},
		{From: 1, To: 2, Mappings: []PortMapping{{1, 2, 3}}},
		{Mappings: []PortMapping{{1, 2, 3}, {2, 4, 10}}}, {Mappings: []PortMapping{{1, 2, 3}, {4, 5, 4}}},
	} {
		if bad.Validate() == nil {
			t.Fatalf("accepted invalid policy %+v", bad)
		}
	}
	legacy := IngressPorts{From: 20000, To: 20099, Offset: 10000}
	if legacy.Validate() != nil || legacy.EntryPort(20099) != 30099 || legacy.Check(19999) == nil {
		t.Fatal("legacy range broken")
	}
	if (IngressPorts{}).Check(443) != nil {
		t.Fatal("legacy unrestricted range broken")
	}
}

func TestIngressMieruSecondPort(t *testing.T) {
	ib := Inbound{Protocol: Mieru, Port: 20001, MieruTransport: "BOTH"}
	for _, p := range []IngressPorts{
		{From: 20001, To: 20001}, {Reserved: []int{20002}},
		{Mappings: []PortMapping{{20001, 20001, 30001}, {20002, 20002, 40002}}},
	} {
		if p.CheckInbound(ib) == nil {
			t.Fatal("second listener escaped policy", p)
		}
	}
	if err := (IngressPorts{Mappings: []PortMapping{{20001, 20002, 30001}}}).CheckInbound(ib); err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{"0.0.0.0", "::", "10.10.0.3"} {
		if CheckIngressListen("10.10.0.2", listen) == nil {
			t.Fatal("bind override allowed", listen)
		}
	}
	if CheckIngressListen("10.10.0.2", "") != nil || CheckIngressListen("2001:db8::1", "2001:db8:0:0::1") != nil {
		t.Fatal("valid inherited/equal bind rejected")
	}
}
