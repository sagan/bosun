package spec

import "strings"

// PublicLabel reports whether s is fit for a label the public status page
// renders: no control characters and none of the characters that would let
// an operator-chosen name become markup when a client interpolates it
// (chart tooltips and legends build HTML strings). The browser escapes
// correctly in the ported theme now, but the server stays the backstop so
// a future client cannot reintroduce the hole. Plain stays for machine
// configuration, where quotes and brackets are legitimate.
func PublicLabel(s string) bool {
	return Plain(s) && !strings.ContainsAny(s, "<>&\"'`")
}
