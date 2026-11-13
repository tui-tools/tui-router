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
	"errors"
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
	// bsVerifyKey: no key this machine trusts verified the artifact; type the
	// public key to verify it with, or nothing to continue without
	// verification.
	bsVerifyKey
	// bsWorking: a read or an apply is in flight.
	bsWorking
	// bsExportPlan: what the export will write, before it writes it.
	bsExportPlan
	// bsRestorePlan: the diff, the reload plan and any hardware warning.
	bsRestorePlan
	// bsHardwareConfirm: the extra typed confirmation a NIC-name mismatch
	// requires, shown before the ordinary one.
	bsHardwareConfirm
	// bsTrustConfirm: the extra typed confirmation an artifact whose signature
	// was not verified requires, shown in the danger colour before the
	// ordinary one.
	bsTrustConfirm
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
	// verifyKey is the public key file the operator named to verify the
	// artifact's signature, empty when none was named.
	verifyKey string
	// keyAsked reports that the key prompt was shown for this restore, so a
	// second unverified open goes to the plan rather than asking again.
	keyAsked bool
	// checked is how the signature check went.
	checked verification

	// The export plan's material.
	sources backup.Sources
	// signer is the machine's signing key; keyPlan, when the machine has none
	// yet, the previewed steps that create it; keyErr why neither is
	// available, in which case only an unsigned export is offered.
	signer  backup.Signer
	keyPlan *router.KeyCreation
	keyErr  string

	// The restore plan's material.
	artifact *backup.Artifact
	preview  backup.Preview
	reloads  []router.ReloadStep
	warning  string
	// findings are the lines the content gate refuses; any one blocks the
	// restore.
	findings []router.RestoreFinding

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
		signer  backup.Signer
		keyPlan *router.KeyCreation
		keyErr  string
		err     string
	}
	backupOpenedMsg struct {
		artifact *backup.Artifact
		checked  verification
		preview  backup.Preview
		reloads  []router.ReloadStep
		warning  string
		findings []router.RestoreFinding
		err      string
	}
	backupWroteMsg struct {
		output string
		err    string
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
		s.signer, s.keyPlan, s.keyErr = msg.signer, msg.keyPlan, msg.keyErr
		s.step = bsExportPlan
		return nil
	case backupOpenedMsg:
		if msg.err != "" {
			return s.fail(msg.err)
		}
		if msg.artifact.Signed && !msg.artifact.SignatureVerified && !s.keyAsked {
			// None of the machine's keys verified it: ask which key does.
			// An unsigned artifact has nothing to verify, so it goes straight
			// to the plan and its trust confirmation.
			s.keyAsked = true
			s.askForKey()
			return nil
		}
		s.artifact = msg.artifact
		s.checked = msg.checked
		s.preview = msg.preview
		s.reloads = msg.reloads
		s.warning = msg.warning
		s.findings = msg.findings
		s.step = bsRestorePlan
		return nil
	case backupWroteMsg:
		if msg.err != "" {
			return s.fail(msg.err)
		}
		s.output = msg.output
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
	case bsPath, bsVerifyKey, bsHardwareConfirm, bsTrustConfirm, bsConfirm:
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
	case bsVerifyKey:
		s.verifyKey = value
		s.step = bsWorking
		return s.openCmd()
	case bsHardwareConfirm:
		if value != hardwarePhrase {
			return s.fail("the hardware confirmation did not match; nothing was applied")
		}
		return s.trustOrConfirm()
	case bsTrustConfirm:
		if value != trustPhrase {
			return s.fail("the trust confirmation did not match; nothing was applied")
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

// trustPhrase is what the operator types to restore an artifact whose
// signature was not verified. Like the hardware phrase it is not "yes": it
// names what is being accepted.
const trustPhrase = "trust unsigned"

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
	// The machine's own key and its trusted keys are tried first: an
	// artifact this machine exported verifies without a question.
	return s.openCmd()
}

// askForKey opens the key prompt for a signed artifact no trusted key
// verified. The public key export wrote beside the artifact is offered as the
// default, with its fingerprint — never used on its own, because it travels
// with the artifact and so proves nothing until the operator has compared that
// fingerprint with the one they recorded.
func (s *backupScreen) askForKey() {
	value := ""
	help := "The public key of the machine that exported it, from a copy kept apart from " +
		"the backup (or place it in " + trustedKeysDir(keyStoreFor(s.backend)) + "). " +
		"Empty: continue unverified, which asks you to type that you trust it."
	if key, ok := besideKey(s.path); ok {
		value = key.Path
		help = "Beside the artifact: " + key.Path + ", fingerprint " + key.Fingerprint() + ". " +
			"It travels with the backup, so it proves nothing by itself: keep it only if that " +
			"fingerprint matches the one you recorded at export. Empty: continue unverified."
	}
	s.input = ui.NewInput("No key this machine trusts verifies it. Verify with which public key?",
		"empty: continue unverified", value)
	s.input.Help = help
	s.step = bsVerifyKey
}

// keyExportPlan is the export confirmation: y writes it signed (creating the
// machine's key first when the plan showed that step), u writes it unsigned.
func (s *backupScreen) keyExportPlan(key string) tea.Cmd {
	switch strings.ToLower(key) {
	case "y", "enter":
		if s.signer == nil && s.keyPlan == nil {
			s.status = "cannot sign: " + s.keyErr + " (u writes it unsigned)"
			return nil
		}
		s.step = bsWorking
		return s.writeCmd(true)
	case "u":
		s.step = bsWorking
		return s.writeCmd(false)
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
		if len(s.findings) > 0 {
			return s.fail((&router.RestoreRefusedError{Findings: s.findings}).Error())
		}
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
		return s.trustOrConfirm()
	case "n", "esc", "q":
		s.closed = true
	}
	return nil
}

// trustOrConfirm asks for the trust phrase when the artifact's signature was
// not verified, and goes straight to the ordinary confirmation when it was.
func (s *backupScreen) trustOrConfirm() tea.Cmd {
	if s.artifact != nil && s.artifact.SignatureVerified {
		return s.openConfirm()
	}
	s.input = ui.NewInput("Trust this unverified artifact?", trustPhrase, "")
	s.step = bsTrustConfirm
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
		if err != nil {
			return backupCollectedMsg{err: err.Error()}
		}
		msg := backupCollectedMsg{sources: src}
		store := keyStoreFor(backend)
		msg.signer, err = store.LocalSigner(ctx)
		if errors.Is(err, router.ErrNoSigningKey) {
			msg.keyPlan, err = store.PlanCreate()
		}
		msg.keyErr = errString(err)
		return msg
	}
}

// writeCmd assembles and writes the artifact the plan described: signed with
// the machine's key — created first, with the steps the plan showed, when the
// machine has none — or unsigned when the operator chose that.
func (s *backupScreen) writeCmd(sign bool) tea.Cmd {
	backend, src, path := s.backend, s.sources, s.path
	signer, keyPlan := s.signer, s.keyPlan
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), backupScreenTimeout)
		defer cancel()
		store := keyStoreFor(backend)
		if !sign {
			signer = nil
		} else if signer == nil {
			created, err := store.Create(ctx, keyPlan)
			if err != nil {
				return backupWroteMsg{err: "creating the signing key: " + err.Error()}
			}
			signer = created
		}
		meta := backup.Meta{
			ToolVersion: version,
			Hostname:    backend.Hostname(),
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
		}
		data, err := backup.Assemble(src, meta, signer)
		if err != nil {
			return backupWroteMsg{err: err.Error()}
		}
		pubPath, err := writeArtifact(path, data, signer)
		if err != nil {
			return backupWroteMsg{err: err.Error()}
		}
		summary := fmt.Sprintf("wrote %s — %d parts, %d bytes", path, countParts(src), len(data))
		if signer == nil {
			return backupWroteMsg{output: summary + ", unsigned.\n" +
				"Restoring it will ask you to type that you trust it."}
		}
		return backupWroteMsg{output: summary + ", signed.\n" +
			signedSummary(signer, pubPath, "this machine's key ("+store.Location()+")")}
	}
}

// openCmd reads and verifies the artifact, then builds everything the restore
// preview shows: the diff against the machine, the reload plan, and the
// hardware warning.
func (s *backupScreen) openCmd() tea.Cmd {
	backend, path, keyPath := s.backend, s.path, s.verifyKey
	return func() tea.Msg {
		data, err := os.ReadFile(path) //nolint:gosec // the path is one the operator typed into the prompt
		if err != nil {
			return backupOpenedMsg{err: "reading the artifact: " + err.Error()}
		}
		art, checked, err := openVerified(data, keyPath, keyStoreFor(backend))
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
			checked:  checked,
			preview:  backup.Diff(current, art.Sources),
			reloads:  backend.ReloadPlan(art.Sources),
			warning:  deviceWarning(ctx, backend, art.Sources),
			findings: router.CheckRestore(art.Sources),
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
	case bsPath, bsVerifyKey, bsHardwareConfirm, bsConfirm:
		return s.input.View(t, width, height)
	case bsTrustConfirm:
		body = s.viewTrust(t, width)
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
		"")
	lines = append(lines, s.exportSignatureLines(t, width)...)
	yes := " write it signed    "
	if s.signer == nil && s.keyPlan != nil {
		yes = " create the key, then write it signed    "
	}
	keys := t.Key.Render("u") + t.KeyDesc.Render(" write it unsigned    ") +
		t.Key.Render("n") + t.KeyDesc.Render(" cancel")
	if s.signer != nil || s.keyPlan != nil {
		keys = t.Key.Render("y") + t.KeyDesc.Render(yes) + keys
	}
	lines = append(lines, "", keys)
	return strings.Join(lines, "\n")
}

// exportSignatureLines says how the export will be signed: with the machine's
// key, after creating it with the previewed steps, or not at all and why.
func (s *backupScreen) exportSignatureLines(t theme.Theme, width int) []string {
	wrap := func(style lipgloss.Style, text string) []string {
		var out []string
		for _, line := range strings.Split(wordWrap(text, width-8), "\n") {
			out = append(out, style.Render("  "+line))
		}
		return out
	}
	lines := []string{t.Muted.Render("Signature:")}
	switch {
	case s.signer != nil:
		lines = append(lines, t.OK.Render(ui.Truncate("  this machine's key "+
			backup.Fingerprint(s.signer.Public()), width-6)))
	case s.keyPlan != nil:
		lines = append(lines, wrap(t.Warn, "This machine has no signing key yet. Signing creates it first ("+
			backup.Fingerprint(s.keyPlan.Public)+"); the private key goes through stdin and stays "+
			"readable by root only:")...)
		for _, step := range s.keyPlan.Steps {
			lines = append(lines, t.Command.Render(ui.Truncate("  $ "+step.Preview, width-6)))
		}
	default:
		lines = append(lines, wrap(t.Danger, "cannot sign: "+s.keyErr)...)
	}
	lines = append(lines, wrap(t.Muted, "The public key is written beside the artifact as .pub. "+signingLimits)...)
	return lines
}

// wordWrap breaks text into lines of at most width cells at spaces.
func wordWrap(text string, width int) string {
	if width < 20 {
		width = 20
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) > width:
			lines = append(lines, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
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
	}
	signature := "Signature: " + signatureStatus(s.artifact, s.checked)
	if s.artifact.SignatureVerified {
		lines = append(lines, t.OK.Render(ui.Truncate(signature, width-6)))
		if s.checked.key.Path == besidePubPath(s.path) {
			lines = append(lines, t.Warn.Render(ui.Truncate(
				"  That key sat beside the artifact: this is only as good as your check of its fingerprint.",
				width-6)))
		}
	} else {
		lines = append(lines, t.Danger.Render(ui.Truncate(signature, width-6)),
			t.Warn.Render("  Applying it will ask you to type '"+trustPhrase+"'."))
	}
	for _, problem := range s.checked.problems {
		lines = append(lines, t.Warn.Render(ui.Truncate("  skipped trusted key: "+problem, width-6)))
	}
	if len(s.findings) > 0 {
		lines = append(lines, "", t.Danger.Render(fmt.Sprintf(
			"BLOCKED — %d line(s) would run a command or load files from elsewhere as root:",
			len(s.findings))))
		for _, f := range s.findings {
			for _, line := range strings.Split(f.String(), "\n") {
				lines = append(lines, t.Danger.Render(ui.Truncate("  "+line, width-6)))
			}
		}
		lines = append(lines, t.Warn.Render("  The restore cannot be applied."))
	}
	lines = append(lines, "", t.Muted.Render("What it would change:"))
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

// viewTrust is the trust confirmation for an artifact whose signature was not
// verified: what is being trusted, in the danger colour, then the prompt.
func (s *backupScreen) viewTrust(t theme.Theme, width int) string {
	what := "This artifact is unsigned."
	switch {
	case s.artifact != nil && s.artifact.Signed && s.checked.named.Path != "":
		what = "Its signature names " + s.checked.named.Fingerprint() +
			", a key this machine trusts, but does not verify: it changed after it was signed."
	case s.artifact != nil && s.artifact.Signed:
		what = "This artifact is signed, but no key this machine trusts verifies it, and none was given."
	}
	text := []string{
		what,
		"Nothing proves who wrote " + s.path + ".",
		"Its checksums do not: anyone who could edit the file could recompute them.",
		"Restoring it trusts that nobody but you changed it since it was exported:",
		"its config files are written and the reload commands run as root.",
		"Lines that would run a command or load other files were already refused.",
	}
	lines := []string{t.Danger.Render("Trust an unverified artifact?"), ""}
	for _, line := range text {
		lines = append(lines, t.Danger.Render(ui.Truncate(line, width-6)))
	}
	lines = append(lines, "",
		t.Base.Render("Type '"+trustPhrase+"' to continue, or esc to cancel:"),
		s.input.Model.View())
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
