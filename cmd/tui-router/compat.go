package main

import (
	"context"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/manifest"
	tuirouter "github.com/tui-tools/tui-router"
)

// probeCompat reads the version of every backend the cockpit talks to. The
// router reads more than one: iproute2 for the interfaces and routes, and,
// where they are present, nftables and wireguard-tools. Each is judged against
// what the embedded tool.json declares, so there is no second copy of the
// minimums in the code.
//
// It never fails. A manifest that cannot be parsed produces no results, and a
// backend this machine does not have produces one with an empty version and a
// reason — on a cockpit, "wireguard-tools is not installed" is worth showing.
func probeCompat(ctx context.Context, demo bool) []compat.Result {
	// --demo drives an in-memory router; probing the host would report
	// versions that have nothing to do with what is on screen.
	if demo {
		return nil
	}
	m, err := manifest.Load(tuirouter.ManifestJSON)
	if err != nil {
		return nil
	}
	results := make([]compat.Result, 0, len(m.Backends))
	for _, backend := range m.Backends {
		results = append(results, compat.Probe(ctx, backend))
	}
	return results
}

// installed keeps the backends that answered with a version — the ones this
// machine actually has. It is what the header shows.
func installed(results []compat.Result) []compat.Result {
	kept := make([]compat.Result, 0, len(results))
	for _, result := range results {
		if result.Version != "" {
			kept = append(kept, result)
		}
	}
	return kept
}
