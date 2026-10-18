package spec

import (
	"strings"
	"testing"
)

func TestHostRequestValidation(t *testing.T) {
	for _, r := range []HostRequest{{Action: "inspect"}, {Action: "apply", Section: "hostname", Revision: strings.Repeat("a", 64), Values: map[string]string{"hostname": "node"}}, {Action: "confirm", Transaction: strings.Repeat("b", 64), Verified: true}, {Action: "rollback", Transaction: strings.Repeat("b", 64)}} {
		if e := r.Validate(); e != nil {
			t.Fatal(r, e)
		}
	}
	for _, r := range []HostRequest{{Action: "shell"}, {Action: "inspect", Values: map[string]string{"command": "id"}}, {Action: "apply", Section: "hostname", Values: map[string]string{"hostname": "node"}}, {Action: "apply", Section: "hostname", Revision: strings.Repeat("a", 64), Values: map[string]string{"command": "id"}}, {Action: "apply", Section: "hostname", Revision: strings.Repeat("a", 64), Values: map[string]string{"hostname": "node\nother"}}, {Action: "confirm", Transaction: strings.Repeat("b", 64)}} {
		if r.Validate() == nil {
			t.Fatal("accepted", r)
		}
	}
}
