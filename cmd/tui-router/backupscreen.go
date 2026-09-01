// The cockpit's backup screen. Export and restore already exist as
// subcommands, and they stay: a backup an operator can script is worth more
// than one they can only click. This screen is the same two flows for the
// operator who is already looking at the router — the export plan before the
// file is written, and for a restore the identical per-subsystem diff, reload
// plan and typed confirmation the command shows, driven by the one apply
// engine in backupcmd.go.
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// backupStep is where the backup screen is in its flow.
type backupStep int

const (
	// bsMenu: choose export or restore.
	bsMenu backupStep = iota
	// bsPath: type the artifact path.
	bsPath
	// bsWorking: a read or an apply is in flight.
	bsWorking
	// bsExportPlan: what the export will write, before it writes it.
	bsExportPlan
	// bsRestorePlan: the diff, the reload plan and any hardware warning.
	bsRestorePlan
	// bsHardwareConfirm: the extra typed confirmation a NIC-name mismatch
	// requires, shown before the ordinary one.
	bsHardwareConfirm
	// bsConfirm: the typed "yes" that applies a restore.
	bsConfirm
	// bsKeep: the ruleset is live and waiting for the connectivity keep.
	bsKeep
	// bsDone: the result.
	bsDone
)

// backupMode is which of the two flows the screen is running.
type backupMode int

const (
	backupExport backupMode = iota
	backupRestore
)

// backupScreen is the model the app drives while the backup screen is open.
type backupScreen struct {
	backend router.BackupBackend
	mode    backupMode
	step    backupStep

	input ui.Input
	path  string

	// The export plan's material.
	sources backup.Sources

	// The restore plan's material.
	artifact *backup.Artifact
	preview  backup.Preview
	reloads  []router.ReloadStep
	warning  string

	// output is what the apply engine printed, shown on the done screen.
	output string
	// failed carries the error of a finished flow, empty when it worked.
	failed string
	status string

	// ask and answer drive the keep-or-rollback confirmation across the
	// goroutine the apply runs in: the engine's keep callback signals ask and
	// blocks on answer, which the keep screen's key press resolves.
	ask    chan struct{}
	answer chan bool

	// closed reports the screen is finished; the app drops it and re-reads.
	closed bool
}

// The backup screen's async results.
type (
	backupCollectedMsg struct {
		sources backup.Sources
		err     string
	}
	backupOpenedMsg struct {
		artifact *backup.Artifact
		preview  backup.Preview
		reloads  []router.ReloadStep
		warning  string
		err      string
	}
	backupWroteMsg struct {
		path  string
		parts int
		bytes int
		err   string
	}
	backupKeepAskMsg struct{}
	backupAppliedMsg struct {
		output string
		err    string
	}
)

// backupScreenTimeout bounds each of the screen's reads and its apply.
const backupScreenTimeout = 5 * time.Minute

// newBackupScreen opens the screen on its menu.
func newBackupScreen(backend router.BackupBackend) *backupScreen {
	return &backupScreen{
		backend: backend,
		ask:     make(chan struct{}, 1),
		answer:  make(chan bool, 1),
	}
}

// Update handles one message while the screen is open.
func (s *backupScreen) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case backupCollectedMsg:
		if msg.err != "" {
			return s.fail("reading the router: " + msg.err)
		}
		s.sources = msg.sources
		s.step = bsExportPlan
		return nil
	case backupOpenedMsg:
		if msg.err != "" {
			return s.fail(msg.err)
		}
		s.artifact = msg.artifact
		s.preview = msg.preview
		s.reloads = msg.reloads
		s.warning = msg.warning
		s.step = bsRestorePlan
		return nil
	case backupWroteMsg:
		if msg.err != "" {
			return s.fail("writing the artifact: " + msg.err)
		}
		s.output = fmt.Sprintf("wrote %s — %d parts, %d bytes, unsigned.\n"+
			"Sign an artifact with: tui-router export --sign KEY --out FILE",
			msg.path, msg.parts, msg.bytes)
		s.step = bsDone
		return nil
	case backupKeepAskMsg:
		s.step = bsKeep
		return nil
	case backupAppliedMsg:
		s.output = msg.output
		s.failed = msg.err
		s.step = bsDone
		return nil
	case tea.KeyMsg:
		return s.handleKey(msg)
	}
	return nil
}

// fail moves the screen to its done step carrying an error.
func (s *backupScreen) fail(message string) tea.Cmd {
	s.failed = message
	s.step = bsDone
	return nil
}

// handleKey routes a key press to the current step.
func (s *backupScreen) handleKey(msg tea.KeyMsg) tea.Cmd {
	if msg.Type == tea.KeyCtrlC {
		s.closed = true
		return nil
	}
	switch s.step {
	case bsMenu:
		return s.keyMenu(msg.String())
	case bsPath, bsHardwareConfirm, bsConfirm:
		return s.keyInput(msg)
	case bsExportPlan:
		return s.keyExportPlan(msg.String())
	case bsRestorePlan:
		return s.keyRestorePlan(msg.String())
	case bsKeep:
		return s.keyKeep(msg.String())
	case bsDone:
		s.closed = true
	}
	return nil
}

// keyMenu picks a flow and moves to the path prompt.
func (s *backupScreen) keyMenu(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "e":
		s.mode = backupExport
		s.input = ui.NewInput("Write the artifact where?",
			defaultArtifactName(s.backend.Hostname(), time.Now().UTC().Format("20060102-150405")), "")
		s.input.Help = "The default name is the placeholder; enter with it empty accepts it."
		s.step = bsPath
	case "r":
		s.mode = backupRestore
		s.input = ui.NewInput("Restore which artifact?", "router-host-stamp"+backup.Extension, "")
		s.input.Help = "The path to a .tuiback file. It is verified before anything is previewed."
		s.step = bsPath
	case "q", "esc":
		s.closed = true
	}
	return nil
}

// keyInput forwards a key to whichever prompt is open and acts on the answer.
func (s *backupScreen) keyInput(msg tea.KeyMsg) tea.Cmd {
	cmd, _ := s.input.Update(msg)
	if !s.input.Done {
		return cmd
	}
	if !s.input.Accepted {
		s.status = "cancelled"
		s.closed = true
		return cmd
	}
	value := s.input.Value()
	switch s.step {
	case bsPath:
		return s.startPath(value)
	case bsHardwareConfirm:
		if value != hardwarePhrase {
			return s.fail("the hardware confirmation did not match; nothing was applied")
		}
		return s.openConfirm()
	case bsConfirm:
		if value != "yes" {
			return s.fail("not confirmed; nothing was applied")
		}
		s.step = bsWorking
		return tea.Batch(s.applyCmd(), s.waitForKeepAsk())
	}
	return cmd
}

// hardwarePhrase is what the operator types to restore an artifact whose
// roles.conf names NICs this machine does not have. It is deliberately not
// "yes": a different phrase cannot be typed by reflex.
const hardwarePhrase = "different hardware"

// startPath resolves the typed path and starts the flow's first read.
func (s *backupScreen) startPath(value string) tea.Cmd {
	if value == "" {
		value = s.input.Model.Placeholder
	}
	if value == "" {
		s.status = "a path is required"
		s.input = ui.NewInput(s.input.Title, s.input.Model.Placeholder, "")
		return nil
	}
	s.path = value
	s.step = bsWorking
	if s.mode == backupExport {
		return s.collectCmd()
	}
	return s.openCmd()
}

// keyExportPlan is the export confirmation.
func (s *backupScreen) keyExportPlan(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "y", "enter":
		s.step = bsWorking
		return s.writeCmd()
	case "n", "esc", "q":
		s.closed = true
	}
	return nil
}

// keyRestorePlan moves from the preview to the typed confirmation — through
// the extra hardware confirmation first when the NIC names do not match.
func (s *backupScreen) keyRestorePlan(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "y", "enter":
		if !s.preview.HasChanges() {
			s.output = "The machine already matches the artifact; nothing to apply."
			s.step = bsDone
			return nil
		}
		if s.warning != "" {
			s.input = ui.NewInput("Restore onto this different hardware?", hardwarePhrase, "")
			s.input.Help = "Type it exactly to continue, or esc to cancel."
			s.step = bsHardwareConfirm
			return nil
		}
		return s.openConfirm()
	case "n", "esc", "q":
		s.closed = true
	}
	return nil
}

// openConfirm shows the typed "yes" that applies the restore.
func (s *backupScreen) openConfirm() tea.Cmd {
	s.input = ui.NewInput("Apply this restore?", "yes", "")
	s.input.Help = "Config files are written, the services above are reloaded, " +
		"then the ruleset applies with a keep-or-rollback confirmation."
	s.step = bsConfirm
	return nil
}

// keyKeep resolves the connectivity confirmation: k keeps the new ruleset,
// anything else lets it roll back to the pre-restore snapshot.
func (s *backupScreen) keyKeep(key string) tea.Cmd {
	keep := strings.ToLower(key) == "k"
	select {
	case s.answer <- keep:
	default:
	}
	s.step = bsWorking
	return nil
}

// collectCmd reads the router for the export plan.
func (s *backupScreen) collectCmd() tea.Cmd {
	backend := s.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backupScreenTimeout)
		defer cancel()
		src, err := backend.CollectSources(ctx)
		return backupCollectedMsg{sources: src, err: errString(err)}
	}
}

// writeCmd assembles and writes the artifact the plan described.
func (s *backupScreen) writeCmd() tea.Cmd {
	backend, src, path := s.backend, s.sources, s.path
	return func() tea.Msg {
		meta := backup.Meta{
			ToolVersion: version,
			Hostname:    backend.Hostname(),
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}
		data, err := backup.Assemble(src, meta, nil)
		if err != nil {
			return backupWroteMsg{err: err.Error()}
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return backupWroteMsg{err: err.Error()}
		}
		return backupWroteMsg{path: path, parts: countParts(src), bytes: len(data)}
	}
}

// openCmd reads and verifies the artifact, then builds everything the restore
// preview shows: the diff against the machine, the reload plan, and the
// hardware warning.
func (s *backupScreen) openCmd() tea.Cmd {
	backend, path := s.backend, s.path
	return func() tea.Msg {
		data, err := os.ReadFile(path) //nolint:gosec // the path is one the operator typed into the prompt
		if err != nil {
			return backupOpenedMsg{err: "reading the artifact: " + err.Error()}
		}
		art, err := backup.Open(data, nil)
		if err != nil {
			return backupOpenedMsg{err: err.Error()}
		}
		ctx, cancel := context.WithTimeout(context.Background(), backupScreenTimeout)
		defer cancel()
		current, err := backend.CollectSources(ctx)
		if err != nil {
			return backupOpenedMsg{err: "reading the router to compare: " + err.Error()}
		}
		return backupOpenedMsg{
			artifact: art,
			preview:  backup.Diff(current, art.Sources),
			reloads:  backend.ReloadPlan(art.Sources),
			warning:  deviceWarning(ctx, backend, art.Sources),
		}
	}
}

// applyCmd runs the same apply engine the restore command runs, with a keep
// callback that hands the decision to the keep screen.
func (s *backupScreen) applyCmd() tea.Cmd {
	backend, target := s.backend, s.artifact.Sources
	ask, answer := s.ask, s.answer
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backupScreenTimeout)
		defer cancel()
		var out bytes.Buffer
		keep := func() bool {
			select {
			case ask <- struct{}{}:
			default:
			}
			select {
			case answer := <-answer:
				return answer
			case <-time.After(backup.DefaultKeepTimeout):
				return false
			}
		}
		err := applyRestore(ctx, backend, target, backup.DefaultKeepTimeout, keep, &out)
		return backupAppliedMsg{output: out.String(), err: errString(err)}
	}
}

// waitForKeepAsk turns the engine's keep signal into a message, so the screen
// switches to the keep prompt exactly when the ruleset goes live.
func (s *backupScreen) waitForKeepAsk() tea.Cmd {
	ask := s.ask
	return func() tea.Msg {
		<-ask
		return backupKeepAskMsg{}
	}
}

// View renders the current step full-screen.
func (s *backupScreen) View(t theme.Theme, width, height int) string {
	var body string
	switch s.step {
	case bsMenu:
		body = s.viewMenu(t)
	case bsPath, bsHardwareConfirm, bsConfirm:
		return s.input.View(t, width, height)
	case bsWorking:
		body = t.Muted.Render("working…")
	case bsExportPlan:
		body = s.viewExportPlan(t, width)
	case bsRestorePlan:
		body = s.viewRestorePlan(t, width)
	case bsKeep:
		body = s.viewKeep(t)
	case bsDone:
		body = s.viewDone(t, width)
	}
	title := t.Title.Render("Backup") + "  " +
		t.Muted.Render("one artifact for the whole router")
	lines := []string{title, "", body}
	if s.status != "" {
		lines = append(lines, "", t.Warn.Render(ui.Truncate(s.status, width-2)))
	}
	return lipgloss.NewStyle().Padding(1, 2).MaxWidth(width).MaxHeight(height).
		Render(strings.Join(lines, "\n"))
}

// viewMenu is the two-way choice.
func (s *backupScreen) viewMenu(t theme.Theme) string {
	return strings.Join([]string{
		t.Base.Render("Export writes one integrity-checked .tuiback file: the role"),
		t.Base.Render("assignment, the networkd units, the forwarding and resolver"),
		t.Base.Render("drop-ins, dnsmasq, the WireGuard configs with their keys stripped,"),
		t.Base.Render("the account names and the nftables ruleset."),
		"",
		t.Base.Render("Restore verifies an artifact, shows you every change it would"),
		t.Base.Render("make, and applies it only after you type the confirmation."),
		"",
		t.Key.Render("e") + t.KeyDesc.Render(" export    ") +
			t.Key.Render("r") + t.KeyDesc.Render(" restore    ") +
			t.Key.Render("esc") + t.KeyDesc.Render(" back to the cockpit"),
	}, "\n")
}

// viewExportPlan is what the export will write, before it writes it.
func (s *backupScreen) viewExportPlan(t theme.Theme, width int) string {
	lines := []string{
		t.Title.Render("Export plan"),
		"",
		t.Muted.Render("File:"),
		t.Command.Render("  " + s.path),
		"",
		t.Muted.Render("Contents:"),
	}
	for _, line := range exportPlanLines(s.sources) {
		lines = append(lines, t.Base.Render(ui.Truncate("  "+line, width-6)))
	}
	lines = append(lines, "",
		t.Base.Render("No secret is written: WireGuard key material is stripped and"),
		t.Base.Render("referenced by path, and accounts carry names and roles only."),
		t.Muted.Render("Unsigned. To sign: tui-router export --sign KEY --out FILE"),
		"",
		t.Key.Render("y")+t.KeyDesc.Render(" write it    ")+
			t.Key.Render("n")+t.KeyDesc.Render(" cancel"))
	return strings.Join(lines, "\n")
}

// exportPlanLines describes what an export of these Sources will carry, one
// line per subsystem that has something to say.
func exportPlanLines(src backup.Sources) []string {
	var lines []string
	add := func(present bool, text string) {
		if present {
			lines = append(lines, text)
		}
	}
	add(strings.TrimSpace(src.Roles) != "", "roles.conf (the WAN/LAN assignment)")
	add(len(src.Networkd) > 0, fmt.Sprintf("%d networkd unit(s)", len(src.Networkd)))
	add(strings.TrimSpace(src.Sysctl) != "", "the forwarding drop-in")
	add(strings.TrimSpace(src.Resolved) != "", "the systemd-resolved drop-in")
	add(strings.TrimSpace(src.DHCPDNS) != "", "the DHCP/DNS config")
	add(len(src.Wireguard) > 0, fmt.Sprintf("%d WireGuard config(s), keys stripped", len(src.Wireguard)))
	add(strings.TrimSpace(src.FirewallRules) != "", "tui-firewall's saved ruleset")
	add(strings.TrimSpace(src.Nftables) != "", "the live nftables ruleset")
	add(len(src.Accounts) > 0, fmt.Sprintf("%d account name(s)", len(src.Accounts)))
	if len(lines) == 0 {
		return []string{"(this machine has nothing any subsystem recognises)"}
	}
	return lines
}

// viewRestorePlan is the diff, the reload plan and the hardware warning — the
// same material the restore command prints, on one screen.
func (s *backupScreen) viewRestorePlan(t theme.Theme, width int) string {
	m := s.artifact.Manifest
	lines := []string{
		t.Title.Render("Restore plan"),
		"",
		t.Base.Render(ui.Truncate(fmt.Sprintf("From %s at %s (tui-router %s)",
			m.Hostname, m.Timestamp, m.ToolVersion), width-6)),
		t.OK.Render("Integrity: checksums verified"),
		t.Muted.Render("Signature: " + signatureStatus(s.artifact, false)),
		"",
		t.Muted.Render("What it would change:"),
	}
	for _, line := range strings.Split(s.preview.String(), "\n") {
		lines = append(lines, t.Base.Render(ui.Truncate(line, width-6)))
	}
	lines = append(lines, "", t.Muted.Render("Then, in order ('!' may drop your session):"))
	for _, line := range strings.Split(reloadPlanBlock(s.reloads), "\n") {
		lines = append(lines, t.Command.Render(ui.Truncate(line, width-6)))
	}
	lines = append(lines,
		t.Muted.Render("  then the nftables ruleset, atomically, with a keep-or-rollback."))
	if s.warning != "" {
		lines = append(lines, "", t.Danger.Render("The hardware does not match:"))
		for _, line := range strings.Split(s.warning, "\n") {
			lines = append(lines, t.Warn.Render(ui.Truncate(line, width-6)))
		}
	}
	lines = append(lines, "",
		t.Key.Render("y")+t.KeyDesc.Render(" continue to the confirmation    ")+
			t.Key.Render("n")+t.KeyDesc.Render(" cancel"))
	return strings.Join(lines, "\n")
}

// viewKeep is the connectivity confirmation, the same contract the command's
// keep prompt carries.
func (s *backupScreen) viewKeep(t theme.Theme) string {
	return strings.Join([]string{
		t.Danger.Render("The restored ruleset is live."),
		"",
		t.Base.Render(fmt.Sprintf(
			"Confirm within %s that you still have access, or it rolls back on",
			backup.DefaultKeepTimeout)),
		t.Base.Render("its own to the ruleset this machine had before the restore."),
		"",
		t.Key.Render("k") + t.KeyDesc.Render(" I still have access, keep it    ") +
			t.Key.Render("any other key") + t.KeyDesc.Render(" roll back now"),
	}, "\n")
}

// viewDone is the result of whichever flow ran.
func (s *backupScreen) viewDone(t theme.Theme, width int) string {
	var lines []string
	if s.failed != "" {
		lines = append(lines, t.Danger.Render("Failed"), "")
		for _, line := range strings.Split(s.failed, "\n") {
			lines = append(lines, t.Base.Render(ui.Truncate(line, width-6)))
		}
	} else {
		lines = append(lines, t.OK.Render("Done"))
	}
	if s.output != "" {
		lines = append(lines, "")
		for _, line := range strings.Split(strings.TrimRight(s.output, "\n"), "\n") {
			lines = append(lines, t.Base.Render(ui.Truncate(line, width-6)))
		}
	}
	lines = append(lines, "", t.Key.Render("any key")+t.KeyDesc.Render(" back to the cockpit"))
	return strings.Join(lines, "\n")
}
