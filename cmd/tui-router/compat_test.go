package main

import (
	"context"
	"testing"

	"github.com/tui-tools/tui-kit/manifest"
	tuirouter "github.com/tui-tools/tui-router"
)

// The embedded manifest is what the header and --report read. This test keeps
// its backends block from going malformed unnoticed.
func TestEmbeddedManifestDeclaresItsBackends(t *testing.T) {
	m, err := manifest.Load(tuirouter.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded tool.json does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Errorf("manifest name = %q, want %q", m.Name, toolName)
	}
	for _, name := range []string{"iproute2", "nftables", "wireguard-tools"} {
		backend, ok := m.Backend(name)
		if !ok {
			t.Errorf("no %s backend in the manifest", name)
			continue
		}
		if len(backend.VersionCommand) == 0 {
			t.Errorf("the %s backend declares no version command", name)
		}
	}
}

func TestProbeCompatSkipsDemo(t *testing.T) {
	if got := probeCompat(context.Background(), true); got != nil {
		t.Errorf("demo probe = %+v, want nil", got)
	}
}

// The probe runs against whatever this machine has. It must produce a result
// per declared backend either way — a compatibility probe never fails a tool.
func TestProbeCompatOnThisMachine(t *testing.T) {
	got := probeCompat(context.Background(), false)
	if len(got) != 3 {
		t.Fatalf("got %d results, want one per declared backend", len(got))
	}
	for _, r := range got {
		t.Logf("this machine: %s %s (%s)", r.Backend, r.Version, r.Status)
	}
}
