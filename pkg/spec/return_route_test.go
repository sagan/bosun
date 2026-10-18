package spec

import "testing"

func TestReturnRouteValidation(t *testing.T) {
	req := DiagnosticRequest{Type: "return_route", Route: &ReturnRouteRequest{City: "beijing", Family: "ipv4"}}
	if req.Validate() != nil {
		t.Fatal(req.Validate())
	}
	for _, r := range []DiagnosticRequest{
		{Type: "return_route"},
		{Type: "return_route", Target: "192.0.2.10", Route: req.Route},
		{Type: "return_route", SourceIP: "10.10.0.2", Route: req.Route},
		{Type: "tcp", Target: "example.com:443", Route: req.Route},
		{Type: "return_route", Route: &ReturnRouteRequest{City: "--help", Family: "ipv4"}},
		{Type: "return_route", Route: &ReturnRouteRequest{City: "beijing", Family: "both"}},
	} {
		if r.Validate() == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
