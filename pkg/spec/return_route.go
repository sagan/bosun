package spec

import "fmt"

const ReturnRouteMinimumVersion = "v0.69.0"

type ReturnRouteRequest struct {
	City   string `json:"city"`
	Family string `json:"family"`
}

func (r ReturnRouteRequest) Validate() error {
	if r.City != "beijing" && r.City != "shanghai" && r.City != "guangzhou" {
		return fmt.Errorf("unknown route city")
	}
	if r.Family != "ipv4" && r.Family != "ipv6" {
		return fmt.Errorf("route family must be ipv4 or ipv6")
	}
	return nil
}

type RouteHop struct {
	Reply string   `json:"reply,omitempty"`
	TTL   int      `json:"ttl"`
	IP    string   `json:"ip,omitempty"`
	RTT   *float64 `json:"rtt_ms,omitempty"`
	ASNs  []uint32 `json:"asns,omitempty"`
}
type RouteEvidence struct {
	Code string `json:"code"`
	Hops []int  `json:"hops"`
}
type RoutePath struct {
	Carrier        string          `json:"carrier"`
	Target         string          `json:"target"`
	Outcome        string          `json:"outcome"`
	Reached        bool            `json:"reached"`
	Hops           []RouteHop      `json:"hops"`
	Evidence       []RouteEvidence `json:"evidence"`
	Classification string          `json:"classification"`
	ASNMissing     int             `json:"asn_missing"`
}
type ReturnRouteResult struct {
	City         string      `json:"city"`
	Family       string      `json:"family"`
	Engine       string      `json:"engine"`
	Protocol     string      `json:"protocol"`
	RulesVersion string      `json:"rules_version"`
	ASNProvider  string      `json:"asn_provider"`
	Paths        []RoutePath `json:"paths"`
}
