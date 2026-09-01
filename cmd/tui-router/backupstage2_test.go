package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// TestDemoRoundTripAfterMutation is the acceptance the feature owes: export the
// demo router, change it underneath, restore the artifact, and end up with the
// state the artifact described — including the role assignment, the forwarding
// and resolver drop-ins and tui-firewall's saved ruleset, which stage 1 did not
// carry at all.
func TestDemoRoundTripAfterMutation(t *testing.T) {
	ctx := context.Background()
	machine := router.NewFake()
	before, err := machine.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := backup.Assemble(before,
		backup.Meta{ToolVersion: "test", Hostname: "demo-router", Timestamp: "20260101-000000"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Mutate every subsystem the artifact carries, so the restore has real
	// work to do rather than agreeing with a machine that never changed.
	mutations := []struct{ subsystem, name, content string }{
		{backup.SubsystemRoles, "", "WAN_IFS=\"eth1\"\nLAN_IFS=\"eth0\"\n"},
		{backup.SubsystemSysctl, "", "net.ipv4.ip_forward=0\n"},
		{backup.SubsystemResolved, "", "[Resolve]\nDNS=198.51.100.53\n"},
		{backup.SubsystemFirewallRules, "", "table inet filter {\n}\n"},
		{backup.SubsystemDHCPDNS, "", "interface=eth9\n"},
		{backup.SubsystemNetworkd, "10-wan0.network", "[Match]\nName=nope\n"},
	}
	for _, m := range mutations {
		if err := machine.WriteConfig(ctx, m.subsystem, m.name, m.content); err != nil {
			t.Fatalf("mutating %s: %v", m.subsystem, err)
		}
	}
	if err := machine.ApplyNftables(ctx, "flush ruleset\ntable inet filter {\n}\n"); err != nil {
		t.Fatal(err)
	}

	mutated, err := machine.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !backup.Diff(mutated, before).HasChanges() {
		t.Fatal("the mutation changed nothing, so the restore would prove nothing")
	}

	art, err := backup.Open(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := applyRestore(ctx, machine, art.Sources, time.Second,
		func() bool { return true }, &out); err != nil {
		t.Fatalf("applyRestore: %v\n%s", err, out.String())
	}

	after, err := machine.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := backup.Diff(after, before); diff.HasChanges() {
		t.Fatalf("the restore did not put the router back:\n%s\n%s", diff.String(), out.String())
	}

	// The restore has to reload what it wrote; a config file on disk that
	// nothing re-read is not a restored router.
	reloaded := strings.Join(machine.Reloads(), "\n")
	for _, want := range []string{
		"networkctl reload",
		"systemctl restart systemd-resolved",
		"systemctl restart dnsmasq",
		"sysctl --system",
		"wg-quick down wg0",
		"wg-quick up wg0",
	} {
		if !strings.Contains(reloaded, want) {
			t.Errorf("the restore never ran %q; it ran:\n%s", want, reloaded)
		}
	}
}

// TestRestorePreviewsTheReloadPlan asserts --dry-run shows the operator every
// command the apply would run, before anything is applied.
func TestRestorePreviewsTheReloadPlan(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "demo.tuiback")
	var out bytes.Buffer
	if err := runExport([]string{"--demo", "--out", artifact}, "stamp", &out); err != nil {
		t.Fatalf("export: %v", err)
	}

	out.Reset()
	if err := runRestore([]string{"--demo", "--dry-run", artifact},
		strings.NewReader(""), &out); err != nil {
		t.Fatalf("restore --dry-run: %v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{
		"roles/roles.conf",
		"sysctl/forwarding",
		"resolved/drop-in",
		"firewall-rules/saved ruleset",
		"networkctl reload",
		"wg-quick up wg0",
		"nothing was applied",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the restore preview is missing %q:\n%s", want, text)
		}
	}
}

// TestRestoreRefusesDifferentHardwareWithoutTheExtraConfirm asserts the
// NIC-name guard: an artifact whose roles.conf assigns a port this machine does
// not have is warned about, and the ordinary "yes" alone does not apply it.
func TestRestoreRefusesDifferentHardwareWithoutTheExtraConfirm(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "elsewhere.tuiback")

	// An artifact from a machine whose ports are named enp1s0/enp2s0 — names
	// the demo router does not carry.
	src := backup.Sources{
		Roles:  "WAN_IFS=\"enp1s0\"\nLAN_IFS=\"enp2s0\"\n",
		Sysctl: "net.ipv4.ip_forward=1\n",
	}
	data, err := backup.Assemble(src,
		backup.Meta{ToolVersion: "test", Hostname: "other-router", Timestamp: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeRawFile(t, artifact, data)

	// Typing only the ordinary confirmation must not apply it.
	var out bytes.Buffer
	if err := runRestore([]string{"--demo", artifact}, strings.NewReader("yes\n"), &out); err != nil {
		t.Fatalf("restore: %v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "enp1s0") || !strings.Contains(text, "WARNING") {
		t.Errorf("the restore did not warn about the missing devices:\n%s", text)
	}
	if !strings.Contains(text, "Aborted") {
		t.Errorf("the restore applied without the hardware confirmation:\n%s", text)
	}

	// With the phrase typed first, the restore proceeds to the ordinary
	// confirmation and applies.
	out.Reset()
	if err := runRestore([]string{"--demo", artifact},
		strings.NewReader("different hardware\nyes\nkeep\n"), &out); err != nil {
		t.Fatalf("confirmed restore: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "wrote roles.conf") {
		t.Errorf("the confirmed restore wrote nothing:\n%s", out.String())
	}
}

// TestCockpitBackupKeyOpensTheScreen asserts B reaches the backup screen and
// that the screen names both flows.
func TestCockpitBackupKeyOpensTheScreen(t *testing.T) {
	fake := router.NewFake()
	a := newApp(fake, theme.New(), nil)
	a.width, a.height = 120, 40
	snap, _ := fake.Read(context.Background())
	a.loading = false
	a.cur = &snap
	a.rebuild()

	model, _ := a.Update(keyRunes("B"))
	a = model.(*app)
	if a.bak == nil {
		t.Fatal("B should open the backup screen")
	}
	view := a.View()
	if !strings.Contains(view, "export") || !strings.Contains(view, "restore") {
		t.Errorf("the backup menu must offer both flows:\n%s", view)
	}
}

// TestBackupScreenExportFlow drives the cockpit's export end to end against the
// demo: menu, path prompt, the previewed plan, the confirm, the written file.
func TestBackupScreenExportFlow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cockpit.tuiback")
	s := newBackupScreen(router.NewFake())

	stepScreen(t, s, keyRunes("e"))
	if s.step != bsPath {
		t.Fatalf("e should open the path prompt, step = %v", s.step)
	}
	for _, r := range path {
		stepScreen(t, s, keyRunes(string(r)))
	}
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsExportPlan {
		t.Fatalf("the export plan should be shown, step = %v (%s)", s.step, s.failed)
	}
	plan := s.View(theme.New(), 100, 40)
	for _, want := range []string{"roles.conf", "forwarding drop-in", "keys stripped", path} {
		if !strings.Contains(plan, want) {
			t.Errorf("the export plan is missing %q:\n%s", want, plan)
		}
	}

	stepScreen(t, s, keyRunes("y"))
	if s.step != bsDone || s.failed != "" {
		t.Fatalf("the export did not finish: step=%v failed=%q", s.step, s.failed)
	}

	// The file the screen wrote must be a real artifact the restore path reads.
	var out bytes.Buffer
	if err := runRestore([]string{"--demo", "--dry-run", path},
		strings.NewReader(""), &out); err != nil {
		t.Fatalf("the artifact the cockpit wrote does not verify: %v\n%s", err, out.String())
	}
}

// TestBackupScreenRestoreWarnsOnDifferentHardware asserts the cockpit's
// restore surfaces the same NIC-name warning the command does, and demands the
// extra typed phrase before the ordinary confirmation.
func TestBackupScreenRestoreWarnsOnDifferentHardware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "elsewhere.tuiback")
	data, err := backup.Assemble(
		backup.Sources{Roles: "WAN_IFS=\"enp1s0\"\nLAN_IFS=\"enp2s0\"\n"},
		backup.Meta{ToolVersion: "test", Hostname: "other-router", Timestamp: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeRawFile(t, path, data)

	s := newBackupScreen(router.NewFake())
	stepScreen(t, s, keyRunes("r"))
	for _, r := range path {
		stepScreen(t, s, keyRunes(string(r)))
	}
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsRestorePlan {
		t.Fatalf("the restore plan should be shown, step = %v (%s)", s.step, s.failed)
	}
	if !strings.Contains(s.warning, "enp1s0") {
		t.Errorf("the restore plan does not warn about the missing devices: %q", s.warning)
	}
	view := s.View(theme.New(), 100, 40)
	if !strings.Contains(view, "The hardware does not match") {
		t.Errorf("the warning is not on screen:\n%s", view)
	}

	stepScreen(t, s, keyRunes("y"))
	if s.step != bsHardwareConfirm {
		t.Fatalf("a mismatch must ask for the extra confirmation, step = %v", s.step)
	}
	// The wrong phrase stops the restore rather than falling through to "yes".
	for _, r := range "yes" {
		stepScreen(t, s, keyRunes(string(r)))
	}
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsDone || s.failed == "" {
		t.Fatalf("the wrong phrase should stop the restore: step=%v failed=%q", s.step, s.failed)
	}
}

// stepScreen feeds one message to the backup screen and runs the command it
// returns synchronously, feeding the result back — the test's stand-in for the
// Bubble Tea loop. The keep-wait command is skipped: it blocks by design.
func stepScreen(t *testing.T, s *backupScreen, msg tea.Msg) {
	t.Helper()
	cmd := s.Update(msg)
	if cmd == nil {
		return
	}
	switch s.step {
	case bsPath, bsConfirm, bsHardwareConfirm:
		// A prompt that is still open returns the text input's cursor-blink
		// command, which sleeps. There is nothing to drive there, so the test
		// loop drops it rather than waiting out a blink per keystroke.
		return
	}
	if next := cmd(); next != nil {
		stepScreen(t, s, next)
	}
}
