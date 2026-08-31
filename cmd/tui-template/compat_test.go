package main

import (
	"context"
	"testing"

	"github.com/tui-tools/tui-kit/manifest"
	tuitemplate "github.com/tui-tools/tui-template"
)

// The embedded manifest is what the header reads. A tool started from the
// template inherits this test, so its own backends block cannot be malformed
// for long.
func TestEmbeddedManifestDeclaresItsBackend(t *testing.T) {
	m, err := manifest.Load(tuitemplate.ManifestJSON)
	if err != nil {
		t.Fatalf("the embedded tool.json does not parse: %v", err)
	}
	if m.Name != toolName {
		t.Errorf("manifest name = %q, want %q", m.Name, toolName)
	}
	backend, ok := m.Backend(backendName)
	if !ok {
		t.Fatalf("no %s backend in the manifest", backendName)
	}
	if len(backend.VersionCommand) == 0 {
		t.Error("the backend declares no version command")
	}
}

func TestProbeCompatSkipsDemo(t *testing.T) {
	if got := probeCompat(context.Background(), true); got.Backend != "" {
		t.Errorf("demo probe = %+v, want the zero result", got)
	}
}

// The probe runs against whatever this machine has. It must produce a Result
// either way — that is the promise: a compatibility probe never fails a tool.
func TestProbeCompatOnThisMachine(t *testing.T) {
	got := probeCompat(context.Background(), false)
	if got.Backend != backendName {
		t.Errorf("backend = %q, want %q", got.Backend, backendName)
	}
	t.Logf("this machine: %s %s (%s)", got.Backend, got.Version, got.Status)
}
