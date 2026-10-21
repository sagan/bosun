package spec

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestWireGuardDomainPreferenceValidation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	link := WireGuardLink{Slot: 1, PrivateKey: key, PeerKey: key, ListenPort: 51820, MTU: 1380}
	for _, preference := range []string{"", "ipv4", "ipv6"} {
		link.DomainPreference = preference
		if err := link.Validate(); err != nil {
			t.Fatalf("preference %q: %v", preference, err)
		}
		data, err := json.Marshal(link)
		if err != nil {
			t.Fatal(err)
		}
		var decoded WireGuardLink
		if err := json.Unmarshal(data, &decoded); err != nil || decoded.DomainPreference != preference {
			t.Fatalf("preference %q did not survive JSON: %v", preference, err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		if _, present := fields["domain_preference"]; present != (preference != "") {
			t.Fatal("legacy preference must remain omitted on the wire")
		}
	}
	for _, preference := range []string{"auto", "IPv4", "ipv4 ", " ipv6", "ipv4\nipv6"} {
		link.DomainPreference = preference
		if err := link.Validate(); err == nil {
			t.Fatalf("accepted unsupported preference %q", preference)
		}
	}
}
