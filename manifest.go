// Package tuitemplate exists for one reason: to embed the repository's
// tool.json into the binary.
//
// The manifest is the family's single source of truth about a tool. Since it
// also carries the `backends[]` block — which version of the backend is the
// minimum, which ones have been tested, what changes on the old ones — the
// running binary reads it too, and no version number has to be written into
// the code. go:embed cannot reach outside its own package directory, so the
// embedding package is the module root.
//
// Keep this file when you start a tool from the template: rename the package
// after your tool and leave everything else as it is.
package tuitemplate

import _ "embed"

// ManifestJSON is the repository's tool.json. Pass it to
// tui-kit/manifest.Load.
//
//go:embed tool.json
var ManifestJSON []byte
