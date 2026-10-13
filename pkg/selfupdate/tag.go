package selfupdate

import "regexp"

// tagRE is the only shape a release tag may take before it is spliced into a
// GitHub API path: vMAJOR.MINOR.PATCH with an optional dash pre-release
// label. Anything else (path separators, dots, query characters) is refused
// before any request is built.
var tagRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.]+)?$`)

// ValidTag reports whether v is a well-formed release tag.
func ValidTag(v string) bool { return tagRE.MatchString(v) }
