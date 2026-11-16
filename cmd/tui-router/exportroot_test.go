package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-router/internal/router"
)

// deniedWireguard is what the real collector reports for /etc/wireguard when
// the export does not run as root.
const deniedWireguard = "/etc/wireguard (permission denied)"

// withUnreadableBackend hands the export command a demo router whose
// collection fails the way a run without root does.
func withUnreadableBackend(t *testing.T) {
	t.Helper()
	previous := pickBackupBackend
	pickBackupBackend = func(config.Config, bool) (router.BackupBackend, error) {
		fake := router.NewFake()
		fake.SetUnreadable(deniedWireguard)
		return fake, nil
	}
	t.Cleanup(func() { pickBackupBackend = previous })
}

// TestExportWithoutRootRefuses is the lab finding: an export that cannot read
// /etc/wireguard used to write an artifact without the WireGuard configs and
// say nothing. It now refuses, names what it could not read, says to run as
// root, and writes neither the artifact nor a signing key.
func TestExportWithoutRootRefuses(t *testing.T) {
	keyDir := onMachine(t)
	withUnreadableBackend(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")

	out, err := exportDefault(t, artifact, "yes\n", "--create-key")
	if err == nil {
		t.Fatalf("an export that could not read /etc/wireguard succeeded:\n%s", out)
	}
	want := "export refused: cannot read " + deniedWireguard + ".\n" +
		"Without them the backup would be incomplete, so nothing was written.\n" +
		"Run the export as root: sudo tui-router export"
	if err.Error() != want {
		t.Errorf("refusal =\n%s\nwant\n%s", err, want)
	}
	for _, path := range []string{artifact, artifact + ".pub", filepath.Join(keyDir, router.SigningKeyName)} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s was written by a refused export", path)
		}
	}
	// --no-sign is not a way around it either: the refusal is about content.
	if _, err := exportDefault(t, artifact, "", "--no-sign"); err == nil ||
		!strings.Contains(err.Error(), "export refused") {
		t.Errorf("--no-sign export without root: %v", err)
	}
}

// TestCockpitExportWithoutRootRefuses: the cockpit's export stops at the same
// refusal, before any plan is shown.
func TestCockpitExportWithoutRootRefuses(t *testing.T) {
	onMachine(t)
	fake := router.NewFake()
	fake.SetUnreadable(deniedWireguard)
	artifact := filepath.Join(t.TempDir(), "c.tuiback")

	s := newBackupScreen(fake)
	stepScreen(t, s, keyRunes("e"))
	s.input.Model.SetValue(artifact)
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step == bsExportPlan {
		t.Fatal("the cockpit offered an export plan it could not read in full")
	}
	for _, want := range []string{"export refused: cannot read " + deniedWireguard,
		"nothing was written", "Run the export as root: sudo tui-router"} {
		if !strings.Contains(s.failed, want) {
			t.Errorf("cockpit failure lacks %q: %q", want, s.failed)
		}
	}
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Errorf("the cockpit wrote %s", artifact)
	}
}
