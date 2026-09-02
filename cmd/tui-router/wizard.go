// The roles wizard: the one guided mutation the cockpit carries. A fresh
// router-profile host boots into safe mode — roles.conf exists but assigns
// nothing, so nothing is forwarded — and no family tool could assign the
// WAN/LAN roles. This wizard closes that gap: pick a role for each NIC,
// preview the exact roles.conf diff and the profile's own --preview render,
// confirm the write, then confirm the apply behind a second, danger-colored
// preview that stages a timed revert first. If the apply cuts the SSH session
// off, the revert restores the previous assignment two minutes later; if
// connectivity holds, one more previewed command disarms it.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-router/internal/router"
)

// wizardStep is where the wizard is in its flow.
type wizardStep int

const (
	// wizSelect: mark each NIC WAN / LAN / unassigned, toggle by-MAC pinning.
	wizSelect wizardStep = iota
	// wizLoading: the read-only nics --preview is being fetched.
	wizLoading
	// wizWriteConfirm: step 1 — the roles.conf diff, the profile's preview,
	// and the install command; confirm writes the file.
	wizWriteConfirm
	// wizApplyConfirm: step 2 — the apply with the revert staged first;
	// danger, because the SSH session may drop.
	wizApplyConfirm
	// wizDone: the result, and the connectivity confirmation that disarms
	// the revert.
	wizDone
)

// NIC roles as the selection screen cycles them.
const (
	roleNone = iota
	roleWAN
	roleLAN
)

// wizardNIC is one row of the selection screen.
type wizardNIC struct {
	name string
	mac  string
	ip   string
	up   bool
	role int
	// byMAC pins the role to the NIC's MAC instead of its name, so the
	// assignment survives a kernel rename.
	byMAC bool
}

// wizard is the roles wizard's model, driven by the app while it is open.
type wizard struct {
	mgr  router.RoleManager
	prev router.RolesStatus

	nics   []wizardNIC
	cursor int
	step   wizardStep

	newContent  string
	diff        string
	nicsPreview string
	writePlan   router.WritePlan
	applyPlan   router.ApplyPlan
	result      router.ApplyResult
	applyErr    string

	// waiting blocks a second confirm while a command is in flight.
	waiting bool
	// cancelPending shows the disarm-the-revert confirm on the done screen.
	cancelPending bool
	cancelDone    bool
	written       bool
	status        string
	// closed reports the wizard is finished; the app drops it and reloads.
	closed bool
}

// The wizard's async results.
type (
	wizPreviewMsg struct{ out, err string }
	wizWroteMsg   struct{ err string }
	wizAppliedMsg struct {
		result router.ApplyResult
		err    string
	}
	wizCancelledMsg struct{ err string }
)

// wizardTimeout bounds each of the wizard's commands.
const wizardTimeout = 60 * time.Second

// newWizard builds the selection screen from the snapshot's interfaces,
// pre-seeding each NIC's role from the current assignment so re-running the
// wizard edits rather than starts over.
func newWizard(mgr router.RoleManager, status router.RolesStatus,
	ifaces []router.Interface) *wizard {
	w := &wizard{mgr: mgr, prev: status}
	assign := status.Parsed.Assignment
	for _, iface := range ifaces {
		if iface.Name == "lo" {
			continue
		}
		nic := wizardNIC{name: iface.Name, mac: iface.MAC, ip: iface.IPv4, up: iface.Up}
		switch {
		case contains(assign.WANIfs, iface.Name):
			nic.role = roleWAN
		case contains(assign.WANMacs, iface.MAC):
			nic.role, nic.byMAC = roleWAN, true
		case contains(assign.LANIfs, iface.Name):
			nic.role = roleLAN
		case contains(assign.LANMacs, iface.MAC):
			nic.role, nic.byMAC = roleLAN, true
		}
		w.nics = append(w.nics, nic)
	}
	return w
}

// contains reports whether a set carries a member.
func contains(set []string, member string) bool {
	if member == "" {
		return false
	}
	for _, m := range set {
		if m == member {
			return true
		}
	}
	return false
}

// assignment builds the RoleAssignment the selection screen describes: each
// NIC lands in its role's name set, or its MAC set when pinned by MAC.
func (w *wizard) assignment() router.RoleAssignment {
	var a router.RoleAssignment
	for _, nic := range w.nics {
		switch nic.role {
		case roleWAN:
			if nic.byMAC && nic.mac != "" {
				a.WANMacs = append(a.WANMacs, nic.mac)
			} else {
				a.WANIfs = append(a.WANIfs, nic.name)
			}
		case roleLAN:
			if nic.byMAC && nic.mac != "" {
				a.LANMacs = append(a.LANMacs, nic.mac)
			} else {
				a.LANIfs = append(a.LANIfs, nic.name)
			}
		}
	}
	return a
}

// Update handles one message while the wizard is open. It returns a command
// to run; the app closes the wizard when w.closed goes true.
func (w *wizard) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case wizPreviewMsg:
		w.waiting = false
		w.nicsPreview = msg.out
		if msg.err != "" {
			w.nicsPreview = "(omarchy-router-nics --preview failed: " + msg.err + ")"
		}
		w.step = wizWriteConfirm
		return nil
	case wizWroteMsg:
		w.waiting = false
		if msg.err != "" {
			w.status = "write failed: " + msg.err
			w.step = wizSelect
			return nil
		}
		w.written = true
		w.applyPlan = w.mgr.ApplyPlan()
		w.step = wizApplyConfirm
		return nil
	case wizAppliedMsg:
		w.waiting = false
		w.result = msg.result
		w.applyErr = msg.err
		w.step = wizDone
		return nil
	case wizCancelledMsg:
		w.waiting = false
		w.cancelPending = false
		if msg.err != "" {
			w.status = "cancelling the revert failed: " + msg.err
			return nil
		}
		w.cancelDone = true
		return nil
	case tea.KeyMsg:
		return w.handleKey(msg)
	}
	return nil
}

// handleKey routes a key press to the current step.
func (w *wizard) handleKey(msg tea.KeyMsg) tea.Cmd {
	if msg.Type == tea.KeyCtrlC {
		w.closed = true
		return nil
	}
	if w.waiting {
		return nil
	}
	switch w.step {
	case wizSelect:
		return w.keySelect(msg.String())
	case wizWriteConfirm:
		return w.keyWriteConfirm(msg.String())
	case wizApplyConfirm:
		return w.keyApplyConfirm(msg.String())
	case wizDone:
		return w.keyDone(msg.String())
	}
	return nil
}

// keySelect drives the NIC selection screen.
func (w *wizard) keySelect(key string) tea.Cmd {
	switch key {
	case "esc", "q":
		w.closed = true
	case "up", "k":
		if w.cursor > 0 {
			w.cursor--
		}
	case "down", "j":
		if w.cursor < len(w.nics)-1 {
			w.cursor++
		}
	case " ", "space":
		if len(w.nics) > 0 {
			w.nics[w.cursor].role = (w.nics[w.cursor].role + 1) % 3
		}
	case "w":
		if len(w.nics) > 0 {
			w.nics[w.cursor].role = roleWAN
		}
	case "l":
		if len(w.nics) > 0 {
			w.nics[w.cursor].role = roleLAN
		}
	case "u":
		if len(w.nics) > 0 {
			w.nics[w.cursor].role = roleNone
		}
	case "m":
		if len(w.nics) > 0 {
			nic := &w.nics[w.cursor]
			if nic.mac == "" {
				w.status = nic.name + " has no MAC to pin by"
				break
			}
			nic.byMAC = !nic.byMAC
		}
	case "enter":
		return w.buildPreview()
	}
	return nil
}

// buildPreview renders the new roles.conf, diffs it, and fetches the
// profile's read-only preview — the material of step 1.
func (w *wizard) buildPreview() tea.Cmd {
	assign := w.assignment()
	if !assign.Assigned() {
		w.status = "assign at least one WAN and one LAN before continuing"
		return nil
	}
	content, err := router.RenderRolesConf(router.RolesConf{
		Assignment: assign, Extras: w.prev.Parsed.Extras})
	if err != nil {
		w.status = err.Error()
		return nil
	}
	w.newContent = content
	w.diff = router.UnifiedDiff("roles.conf", w.prev.Content, content)
	w.writePlan = w.mgr.WritePlan(content)
	w.status = ""
	w.step = wizLoading
	w.waiting = true
	mgr := w.mgr
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), wizardTimeout)
		defer cancel()
		out, err := mgr.NicsPreview(ctx)
		return wizPreviewMsg{out: out, err: errString(err)}
	}
}

// keyWriteConfirm is step 1's confirm: y writes roles.conf, n returns to the
// selection screen.
func (w *wizard) keyWriteConfirm(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "y", "enter":
		w.waiting = true
		mgr, content := w.mgr, w.newContent
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), wizardTimeout)
			defer cancel()
			return wizWroteMsg{err: errString(mgr.WriteRoles(ctx, content))}
		}
	case "n", "esc", "q":
		w.step = wizSelect
	}
	return nil
}

// keyApplyConfirm is step 2's confirm: y stages the revert and applies, n
// leaves roles.conf written but not applied.
func (w *wizard) keyApplyConfirm(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "y", "enter":
		w.waiting = true
		mgr, prevContent := w.mgr, w.prev.Content
		return func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), wizardTimeout)
			defer cancel()
			result, err := mgr.ApplyRoles(ctx, prevContent)
			return wizAppliedMsg{result: result, err: errString(err)}
		}
	case "n", "esc", "q":
		w.status = "roles.conf written — not applied; run omarchy-router-nics --apply when ready"
		w.closed = true
	}
	return nil
}

// keyDone drives the result screen: c opens the disarm-the-revert confirm,
// y/n resolve it, q closes the wizard.
func (w *wizard) keyDone(key string) tea.Cmd {
	if w.cancelPending {
		switch strings.ToLower(key) {
		case "y", "enter":
			w.waiting = true
			mgr := w.mgr
			return func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), wizardTimeout)
				defer cancel()
				return wizCancelledMsg{err: errString(mgr.CancelRevert(ctx))}
			}
		case "n", "esc":
			w.cancelPending = false
		}
		return nil
	}
	switch key {
	case "c":
		if w.result.RevertScheduled && !w.cancelDone {
			w.cancelPending = true
		}
	case "q", "esc", "enter":
		w.closed = true
	}
	return nil
}

// errString flattens an error for a message struct.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// roleLabel renders a NIC's role column.
func roleLabel(role int) string {
	switch role {
	case roleWAN:
		return "WAN"
	case roleLAN:
		return "LAN"
	default:
		return "—"
	}
}

// View renders the wizard's current step full-screen.
func (w *wizard) View(t theme.Theme, width, height int) string {
	var body string
	switch w.step {
	case wizSelect:
		body = w.viewSelect(t, width)
	case wizLoading:
		body = t.Muted.Render("running omarchy-router-nics --preview…")
	case wizWriteConfirm:
		body = w.viewWriteConfirm(t, width)
	case wizApplyConfirm:
		body = w.viewApplyConfirm(t, width)
	case wizDone:
		body = w.viewDone(t, width)
	}
	title := t.Title.Render("Roles wizard") + "  " +
		t.Muted.Render("assign the WAN and LAN roles")
	lines := []string{title, "", body}
	if w.status != "" {
		lines = append(lines, "", t.Warn.Render(ui.Truncate(w.status, width-2)))
	}
	content := strings.Join(lines, "\n")
	return lipgloss.NewStyle().Padding(1, 2).MaxWidth(width).MaxHeight(height).
		Render(content)
}

// viewSelect renders the NIC table and its key hints.
func (w *wizard) viewSelect(t theme.Theme, width int) string {
	lines := []string{
		t.Base.Render("Mark each NIC's role. A role is a set: several WAN uplinks fail over,"),
		t.Base.Render("several LAN ports are bridged. The same port may carry both."),
		"",
	}
	header := fmt.Sprintf("  %-12s %-5s %-18s %-18s %-5s %s",
		"nic", "link", "ip", "mac", "role", "pin")
	lines = append(lines, t.Muted.Render(header))
	for i, nic := range w.nics {
		link := "down"
		if nic.up {
			link = "up"
		}
		ip := nic.ip
		if ip == "" {
			ip = "—"
		}
		mac := nic.mac
		if mac == "" {
			mac = "—"
		}
		pin := "by name"
		if nic.byMAC {
			pin = "by MAC"
		}
		row := fmt.Sprintf("%-12s %-5s %-18s %-18s %-5s %s",
			nic.name, link, ip, mac, roleLabel(nic.role), pin)
		switch {
		case i == w.cursor:
			lines = append(lines, t.SelRow.Render("> "+row))
		case nic.role != roleNone:
			lines = append(lines, t.OK.Render("  "+row))
		default:
			lines = append(lines, t.Row.Render("  "+row))
		}
	}
	lines = append(lines, "",
		t.Key.Render("space")+t.KeyDesc.Render(" cycle role  ")+
			t.Key.Render("w/l/u")+t.KeyDesc.Render(" wan/lan/unassign  ")+
			t.Key.Render("m")+t.KeyDesc.Render(" pin by MAC  ")+
			t.Key.Render("enter")+t.KeyDesc.Render(" preview  ")+
			t.Key.Render("esc")+t.KeyDesc.Render(" cancel"))
	_ = width
	return strings.Join(lines, "\n")
}

// viewWriteConfirm renders step 1: the diff, the profile's preview, and the
// exact install command, above a y/n.
func (w *wizard) viewWriteConfirm(t theme.Theme, width int) string {
	lines := []string{t.Title.Render("Step 1 of 2 — write roles.conf")}
	lines = append(lines, "", t.Muted.Render("The change:"))
	for _, l := range strings.Split(strings.TrimRight(w.diff, "\n"), "\n") {
		switch {
		case strings.HasPrefix(l, "+"):
			lines = append(lines, t.OK.Render(ui.Truncate(l, width-6)))
		case strings.HasPrefix(l, "-"):
			lines = append(lines, t.Danger.Render(ui.Truncate(l, width-6)))
		default:
			lines = append(lines, t.Muted.Render(ui.Truncate(l, width-6)))
		}
	}
	lines = append(lines, "", t.Muted.Render("omarchy-router-nics --preview says:"))
	for _, l := range strings.Split(strings.TrimRight(w.nicsPreview, "\n"), "\n") {
		lines = append(lines, t.Base.Render(ui.Truncate(l, width-6)))
	}
	lines = append(lines, "",
		t.Muted.Render("Command to run:"),
		t.Command.Render("$ "+w.writePlan.Preview),
		"",
		t.Key.Render("y")+t.KeyDesc.Render(" write roles.conf    ")+
			t.Key.Render("n")+t.KeyDesc.Render(" back"))
	return strings.Join(lines, "\n")
}

// viewApplyConfirm renders step 2: the danger apply, with the revert staged
// first and every command shown.
func (w *wizard) viewApplyConfirm(t theme.Theme, width int) string {
	lines := []string{
		t.Danger.Render("Step 2 of 2 — apply the new mapping"),
		"",
		t.Base.Render("This rewrites the .network units and reloads networkd."),
		t.Danger.Render("If you are connected over SSH, this session may drop."),
		"",
	}
	if w.applyPlan.HasSystemdRun {
		lines = append(lines,
			t.Base.Render(fmt.Sprintf(
				"A revert is staged first: unless you confirm connectivity within %d seconds",
				int(router.RevertDelay.Seconds()))),
			t.Base.Render("after the apply, the previous assignment is restored and re-applied."),
			"")
	}
	lines = append(lines, t.Muted.Render("Commands to run, in order:"))
	lines = append(lines, t.Command.Render("$ "+w.applyPlan.StagePreview))
	if w.applyPlan.SchedulePreview != "" {
		lines = append(lines, t.Command.Render("$ "+w.applyPlan.SchedulePreview))
	}
	lines = append(lines, t.Command.Render("$ "+w.applyPlan.ApplyPreview))
	if !w.applyPlan.HasSystemdRun {
		lines = append(lines, "")
		for _, l := range w.applyPlan.ManualRevert {
			lines = append(lines, t.Warn.Render(ui.Truncate(l, width-6)))
		}
	}
	lines = append(lines, "",
		t.Key.Render("y")+t.KeyDesc.Render(" apply    ")+
			t.Key.Render("n")+t.KeyDesc.Render(" keep the file, do not apply"))
	return strings.Join(lines, "\n")
}

// viewDone renders the result and the connectivity confirmation.
func (w *wizard) viewDone(t theme.Theme, width int) string {
	var lines []string
	if w.applyErr != "" {
		lines = append(lines, t.Danger.Render("Apply failed"), "",
			t.Base.Render(ui.Truncate(w.applyErr, width-6)))
	} else {
		lines = append(lines, t.OK.Render("Applied"), "",
			t.Base.Render(ui.Truncate(router.AppliedSummary, width-6)))
	}
	// The command's combined output carries its stderr, which on some
	// machines is only a library warning. It is shown, because a reader may
	// need it, but muted and under a heading that names its source — never as
	// the verdict, which the tool states itself above.
	if w.result.Output != "" {
		lines = append(lines, "", t.Muted.Render(router.ApplyOutputHeading))
		for _, l := range strings.Split(w.result.Output, "\n") {
			lines = append(lines, t.Muted.Render(ui.Truncate(l, width-6)))
		}
	}
	switch {
	case w.cancelPending:
		lines = append(lines, "",
			t.Title.Render("Confirm connectivity — cancel the revert?"),
			"",
			t.Muted.Render("Command to run:"),
			t.Command.Render("$ "+w.applyPlan.CancelPreview),
			"",
			t.Key.Render("y")+t.KeyDesc.Render(" the connection holds, keep this mapping    ")+
				t.Key.Render("n")+t.KeyDesc.Render(" not yet"))
	case w.cancelDone:
		lines = append(lines, "",
			t.OK.Render("Revert cancelled — the new assignment is permanent."),
			"", t.Key.Render("q")+t.KeyDesc.Render(" close"))
	case w.result.RevertScheduled:
		lines = append(lines, "",
			t.Warn.Render(fmt.Sprintf(
				"A revert to the previous assignment fires in %d seconds unless you confirm.",
				int(router.RevertDelay.Seconds()))),
			"",
			t.Key.Render("c")+t.KeyDesc.Render(" confirm connectivity (cancels the revert)    ")+
				t.Key.Render("q")+t.KeyDesc.Render(" close and let it fire"))
	default:
		if w.applyErr == "" && !w.applyPlan.HasSystemdRun {
			lines = append(lines, "")
			for _, l := range router.ManualRevertInstructions() {
				lines = append(lines, t.Warn.Render(ui.Truncate(l, width-6)))
			}
		}
		lines = append(lines, "", t.Key.Render("q")+t.KeyDesc.Render(" close"))
	}
	return strings.Join(lines, "\n")
}
