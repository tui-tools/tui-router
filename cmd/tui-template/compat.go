package main

import (
	"context"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuitemplate "github.com/tui-tools/tui-template"
)

// backendName is the name the manifest gives the backend this tool drives.
// The template drives `touch`, so its example backend is coreutils; yours will
// be ufw, systemd, snapper.
const backendName = "coreutils"

// probeCompat reads the version of the backend the tool is about to drive and
// classifies it against what the manifest declares: below the minimum, tested,
// or merely untested. The result goes in the header through ui.CompatFact, and
// its capability set answers `caps.Has("feature")` for the views that need a
// recent backend.
//
// It never fails. A missing binary, a hung process or unparsable output all
// end as the "version unknown" badge, because a compatibility probe that can
// stop a tool from starting is worse than no probe.
func probeCompat(ctx context.Context, demo bool) compat.Result {
	// --demo drives an in-memory machine, so probing the host would report a
	// version that has nothing to do with what is on screen.
	if demo {
		return compat.Result{}
	}
	m, err := manifest.Load(tuitemplate.ManifestJSON)
	if err != nil {
		return compat.Result{}
	}
	backend, ok := m.Backend(backendName)
	if !ok {
		return compat.Result{}
	}
	return compat.Probe(ctx, backend)
}
