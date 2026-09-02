package main

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/router"
)

// keyRunes builds the key message for typed characters.
func keyRunes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// step feeds one message to the wizard and, when it returns a command, runs
// the command synchronously and feeds its result back — the test's stand-in
// for the Bubble Tea loop.
func step(t *testing.T, w *wizard, msg tea.Msg) {
	t.Helper()
	if cmd := w.Update(msg); cmd != nil {
		if next := cmd(); next != nil {
			step(t, w, next)
		}
	}
}

// demoWizard opens the wizard the way the app does, on the demo backend.
func demoWizard(t *testing.T) (*router.Fake, *wizard) {
	t.Helper()
	fake := router.NewFake()
	snap, err := fake.Read(context.Background())
	if err != nil {
		t.Fatalf("demo read: %v", err)
	}
	if !snap.Roles.NeedsWizard() {
		t.Fatal("the demo router should start in safe mode, needing the wizard")
	}
	return fake, newWizard(fake, snap.Roles, snap.Interfaces)
}

func TestWizardSelectRenders(t *testing.T) {
	_, w := demoWizard(t)
	view := w.View(theme.New(), 120, 40)
	for _, want := range []string{
		"Roles wizard", "eth0", "eth1", "wg0", "eth2",
		"00:00:5e:00:53:10", // the NIC's MAC, for by-MAC pinning
		"198.51.100.20",     // its current IP
	} {
		if !strings.Contains(view, want) {
			t.Errorf("selection screen lacks %q", want)
		}
	}
}

func TestWizardRoleCycleAndMACPin(t *testing.T) {
	_, w := demoWizard(t)
	// space cycles unassigned → WAN → LAN → unassigned.
	step(t, w, keyRunes(" "))
	if w.nics[0].role != roleWAN {
		t.Errorf("after one space, role = %d, want WAN", w.nics[0].role)
	}
	step(t, w, keyRunes(" "))
	step(t, w, keyRunes(" "))
	if w.nics[0].role != roleNone {
		t.Errorf("after three spaces, role = %d, want unassigned", w.nics[0].role)
	}
	// m pins by MAC; the assignment then carries the MAC, not the name.
	step(t, w, keyRunes("w"))
	step(t, w, keyRunes("m"))
	if !w.nics[0].byMAC {
		t.Error("m should pin the NIC by MAC")
	}
	a := w.assignment()
	if len(a.WANMacs) != 1 || a.WANMacs[0] != "00:00:5e:00:53:10" || len(a.WANIfs) != 0 {
		t.Errorf("a MAC-pinned WAN should land in WANMacs, got %+v", a)
	}
	// wg0 (row 2) has no MAC to pin by.
	step(t, w, keyRunes("j"))
	step(t, w, keyRunes("j"))
	step(t, w, keyRunes("m"))
	if w.nics[2].byMAC {
		t.Error("a NIC without a MAC must not be pinnable by MAC")
	}
}

func TestWizardRefusesAHalfAssignment(t *testing.T) {
	_, w := demoWizard(t)
	step(t, w, keyRunes("w")) // WAN only, no LAN
	step(t, w, tea.KeyMsg{Type: tea.KeyEnter})
	if w.step != wizSelect {
		t.Errorf("with no LAN the wizard moved to step %d; it must stay on selection", w.step)
	}
	if !strings.Contains(w.status, "WAN") {
		t.Errorf("status %q should say what is missing", w.status)
	}
}

// The whole demo walk: select, preview, write, apply with the revert armed,
// confirm connectivity, close. This is what --demo lets an operator rehearse.
func TestWizardWalksTheWholeFlowOnTheDemo(t *testing.T) {
	fake, w := demoWizard(t)
	th := theme.New()

	// eth0 → WAN, eth1 → LAN.
	step(t, w, keyRunes("w"))
	step(t, w, keyRunes("j"))
	step(t, w, keyRunes("l"))
	step(t, w, tea.KeyMsg{Type: tea.KeyEnter})

	if w.step != wizWriteConfirm {
		t.Fatalf("after enter, step = %d, want the write confirm", w.step)
	}
	view := w.View(th, 120, 50)
	for _, want := range []string{
		"Step 1 of 2",
		`+WAN_IFS="eth0"`, // the diff
		`+LAN_IFS="eth1"`,
		"unassigned",      // nics --preview still shows the current (empty) mapping
		"Command to run:", // the install preview
		"install -m 644",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("write confirm lacks %q", want)
		}
	}

	step(t, w, keyRunes("y"))
	if w.step != wizApplyConfirm || !w.written {
		t.Fatalf("after y, step = %d written = %v, want the apply confirm", w.step, w.written)
	}
	view = w.View(th, 120, 50)
	for _, want := range []string{
		"Step 2 of 2",
		"session may drop",
		"systemd-run --on-active=120 --unit=tui-router-roles-revert",
		"omarchy-router-nics --apply",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("apply confirm lacks %q", want)
		}
	}

	step(t, w, keyRunes("y"))
	if w.step != wizDone || !w.result.RevertScheduled {
		t.Fatalf("after apply, step = %d revert = %v", w.step, w.result.RevertScheduled)
	}
	view = w.View(th, 120, 50)
	if !strings.Contains(view, "confirm connectivity") {
		t.Errorf("done screen should offer the connectivity confirmation:\n%s", view)
	}

	// c opens the cancel confirm, which previews the systemctl stop.
	step(t, w, keyRunes("c"))
	view = w.View(th, 120, 50)
	if !strings.Contains(view, "systemctl stop tui-router-roles-revert.service tui-router-roles-revert.timer") {
		t.Errorf("cancel confirm should preview the stop command:\n%s", view)
	}
	step(t, w, keyRunes("y"))
	if !w.cancelDone {
		t.Error("confirming connectivity should disarm the revert")
	}

	step(t, w, keyRunes("q"))
	if !w.closed {
		t.Error("q on the done screen should close the wizard")
	}

	// The demo backend's state moved with the flow: the roles are assigned now.
	snap, _ := fake.Read(context.Background())
	if snap.Roles.NeedsWizard() {
		t.Error("after the walk the demo router should no longer need the wizard")
	}
}

func TestWizardDecliningApplyKeepsTheFile(t *testing.T) {
	fake, w := demoWizard(t)
	step(t, w, keyRunes("w"))
	step(t, w, keyRunes("j"))
	step(t, w, keyRunes("l"))
	step(t, w, tea.KeyMsg{Type: tea.KeyEnter})
	step(t, w, keyRunes("y")) // write
	step(t, w, keyRunes("n")) // decline the apply
	if !w.closed {
		t.Error("declining the apply should close the wizard")
	}
	snap, _ := fake.Read(context.Background())
	if snap.Roles.NeedsWizard() {
		t.Error("the written roles.conf should persist even when the apply is declined")
	}
}

func TestPowerDialogRequiresTheTypedWord(t *testing.T) {
	fake := router.NewFake()
	action := powerAction{word: "reboot", preview: fake.RebootPreview(), exec: fake.Reboot}

	// The wrong word cancels.
	d := newPowerDialog(action)
	for _, r := range "yes" {
		d.Update(keyRunes(string(r)))
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !d.done || d.confirmed {
		t.Errorf("typing the wrong word: done=%v confirmed=%v, want done and not confirmed",
			d.done, d.confirmed)
	}

	// The exact word confirms.
	d = newPowerDialog(action)
	view := d.View(theme.New(), 100, 30)
	if !strings.Contains(view, "systemctl reboot") {
		t.Errorf("the dialog must preview the exact command:\n%s", view)
	}
	for _, r := range "reboot" {
		d.Update(keyRunes(string(r)))
	}
	d.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !d.done || !d.confirmed {
		t.Errorf("typing the word: done=%v confirmed=%v, want both", d.done, d.confirmed)
	}

	// Esc cancels.
	d = newPowerDialog(action)
	d.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if !d.done || d.confirmed {
		t.Errorf("esc: done=%v confirmed=%v, want done and not confirmed", d.done, d.confirmed)
	}
}

func TestCockpitShowsTheSafeModeBannerAndOpensTheWizard(t *testing.T) {
	fake := router.NewFake()
	a := newApp(fake, theme.New(), nil)
	a.width, a.height = 120, 40
	snap, _ := fake.Read(context.Background())
	a.loading = false
	a.cur = &snap
	a.rebuild()

	view := a.View()
	if !strings.Contains(view, "roles not assigned") {
		t.Errorf("an unassigned router-profile host must show the banner:\n%s", view)
	}

	// w opens the wizard.
	model, _ := a.Update(keyRunes("w"))
	a = model.(*app)
	if a.wiz == nil {
		t.Fatal("w should open the roles wizard")
	}
	if !strings.Contains(a.View(), "Roles wizard") {
		t.Error("with the wizard open, the wizard owns the screen")
	}
}

func TestCockpitRebootKeyOpensTheTypedConfirm(t *testing.T) {
	fake := router.NewFake()
	a := newApp(fake, theme.New(), nil)
	a.width, a.height = 120, 40
	snap, _ := fake.Read(context.Background())
	a.loading = false
	a.cur = &snap
	a.rebuild()

	model, _ := a.Update(keyRunes("B"))
	a = model.(*app)
	if a.power == nil {
		t.Fatal("B should open the reboot confirm")
	}
	view := a.View()
	if !strings.Contains(view, "systemctl reboot") ||
		!strings.Contains(view, "Type \"reboot\"") {
		t.Errorf("the reboot dialog must preview the command and demand the typed word:\n%s", view)
	}
}

func TestUpdatesCardIsWiredToTuiUpdate(t *testing.T) {
	fake := router.NewFake()
	snap, _ := fake.Read(context.Background())
	cards := router.Cards(snap, nil, fake.ToolInstalled)
	var found bool
	for _, card := range cards {
		if card.Kind == router.CardUpdates {
			found = true
			if card.Tool != "tui-update" {
				t.Errorf("the updates card must launch tui-update, got %q", card.Tool)
			}
			if !strings.Contains(card.Summary, "pending") {
				t.Errorf("demo updates summary = %q, want a pending count", card.Summary)
			}
		}
	}
	if !found {
		t.Error("the cockpit must carry an updates card")
	}
}

// TestWizardDoneStatesItsOwnVerdict is the fix for a result screen that read
// the apply command's first line as the outcome. `omarchy-router-nics --apply`
// runs install(1) underneath, and on a machine whose libsepol and policy
// disagree libselinux writes "Regex version mismatch" to stderr; the runner
// folds stderr into the output, so that warning was what the operator saw
// after a successful apply. The tool's own sentence is the verdict now, and
// the command's output is detail under a heading that names its source.
func TestWizardDoneStatesItsOwnVerdict(t *testing.T) {
	_, w := demoWizard(t)
	w.step = wizDone
	w.result = router.ApplyResult{
		Output:          "libselinux: Regex version mismatch, expected: 10.45 actual: 10.42",
		RevertScheduled: true,
	}

	view := w.View(theme.New(), 120, 50)
	for _, want := range []string{
		"Applied",
		router.AppliedSummary,
		router.ApplyOutputHeading,
		"Regex version mismatch",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("done screen lacks %q:\n%s", want, view)
		}
	}
	// The command's line must come after the tool's own sentence and after the
	// heading that says whose line it is — never in their place.
	summary := strings.Index(view, router.AppliedSummary)
	heading := strings.Index(view, router.ApplyOutputHeading)
	stderr := strings.Index(view, "Regex version mismatch")
	if summary >= heading || heading >= stderr {
		t.Errorf("the command's output must follow the verdict and its heading:\n%s", view)
	}
}
