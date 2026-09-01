package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// backupTimeout bounds the whole export or restore read/apply work.
const backupTimeout = 60 * time.Second

// keepConfirmFunc reports whether the operator confirmed, after the new ruleset
// was applied, that they still have connectivity. Returning false rolls the
// ruleset back. It is a function so a test drives the keep path without a
// terminal, and the interactive command drives it with a timed stdin read.
type keepConfirmFunc func() bool

// pickBackupBackend returns the demo or real backend as a BackupBackend.
func pickBackupBackend(cfg config.Config, demo bool) (router.BackupBackend, error) {
	if demo {
		return router.NewFake(), nil
	}
	return router.New(cfg.SudoPrefix())
}

// backupConfig loads the tool configuration for a subcommand, folding in its
// --sudo override the same way the interactive command does.
func backupConfig(sudo string, sudoSet bool) (config.Config, error) {
	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return config.Config{}, err
	}
	if sudoSet {
		cfg.Set(config.KeySudo, sudo)
	}
	return cfg, nil
}

// runExport reads every subsystem, assembles the artifact and writes it out.
// stamp is passed in from the CLI layer so the pure packages never read a clock.
func runExport(args []string, stamp string, out io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(out)
	var outPath, signKey, sudo string
	var demo bool
	fs.StringVar(&outPath, "out", "", "artifact path (default router-<host>-<stamp>.tuiback)")
	fs.StringVar(&signKey, "sign", "", "sign the artifact with the Ed25519 key in this file")
	fs.BoolVar(&demo, "demo", false, "export the in-memory sample router, no root needed")
	fs.StringVar(&sudo, "sudo", "", "privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-router export [--out FILE] [--sign KEY] [--demo]\n\n"+
			"Read every subsystem and write one integrity-checked .tuiback artifact.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	sudoSet := flagPassed(fs, "sudo")

	cfg, err := backupConfig(sudo, sudoSet)
	if err != nil {
		return err
	}
	backend, err := pickBackupBackend(cfg, demo)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
	defer cancel()

	src, err := backend.CollectSources(ctx)
	if err != nil {
		return fmt.Errorf("reading the router: %w", err)
	}

	var signer backup.Signer
	if signKey != "" {
		signer, err = loadSigner(signKey)
		if err != nil {
			return err
		}
	}

	meta := backup.Meta{
		ToolVersion: version,
		Hostname:    backend.Hostname(),
		Timestamp:   stamp,
	}
	data, err := backup.Assemble(src, meta, signer)
	if err != nil {
		return err
	}

	if outPath == "" {
		outPath = defaultArtifactName(meta.Hostname, stamp)
	}
	if err := os.WriteFile(outPath, data, 0o600); err != nil {
		return fmt.Errorf("writing the artifact: %w", err)
	}

	signed := "no"
	if signer != nil {
		signed = "yes"
	}
	parts := countParts(src)
	_, _ = fmt.Fprintf(out, "wrote %s — %d parts, %d bytes, signed: %s\n",
		outPath, parts, len(data), signed)
	return nil
}

// countParts is how many files an export of these Sources will carry. It is
// what the export summary reports and what the cockpit's export plan previews,
// so the two can never disagree about what is in the artifact.
func countParts(src backup.Sources) int {
	parts := len(src.Networkd) + len(src.Wireguard)
	for _, single := range []string{
		src.Nftables, src.DHCPDNS, src.Roles, src.Sysctl, src.Resolved, src.FirewallRules,
	} {
		if strings.TrimSpace(single) != "" {
			parts++
		}
	}
	if len(src.Accounts) > 0 {
		parts++
	}
	return parts
}

// runRestore opens an artifact, previews it, and — outside --dry-run and after
// one explicit confirmation — applies it with a connectivity-safe rollback.
func runRestore(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(out)
	var verifyKey, sudo string
	var dryRun, demo, keepRuleset bool
	fs.StringVar(&verifyKey, "verify", "", "require a valid signature from the Ed25519 public key in this file")
	fs.BoolVar(&dryRun, "dry-run", false, "verify and preview only; apply nothing")
	fs.BoolVar(&keepRuleset, "keep", false,
		"keep the restored ruleset without the connectivity confirmation "+
			"(for scripted restores or a local console; it bypasses the connectivity guard, "+
			"so only use it when you can reach the box another way)")
	fs.BoolVar(&demo, "demo", false, "restore into the in-memory sample router, no root needed")
	fs.StringVar(&sudo, "sudo", "", "privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-router restore FILE [--verify PUBKEY] [--dry-run] [--keep] [--demo]\n\n"+
			"Verify an artifact, preview it, and apply it after one confirmation.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("restore needs the path to a .tuiback artifact")
	}
	artifactPath := fs.Arg(0)
	sudoSet := flagPassed(fs, "sudo")

	data, err := os.ReadFile(artifactPath) //nolint:gosec // the artifact path is an explicit CLI argument
	if err != nil {
		return fmt.Errorf("reading the artifact: %w", err)
	}

	var verifier backup.Verifier
	if verifyKey != "" {
		verifier, err = loadVerifier(verifyKey)
		if err != nil {
			return err
		}
	}

	art, err := backup.Open(data, verifier)
	if err != nil {
		// A tampered, truncated or unverifiable artifact is refused here.
		return err
	}

	cfg, err := backupConfig(sudo, sudoSet)
	if err != nil {
		return err
	}
	backend, err := pickBackupBackend(cfg, demo)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), backupTimeout)
	defer cancel()

	current, err := backend.CollectSources(ctx)
	if err != nil {
		return fmt.Errorf("reading the router to compare: %w", err)
	}
	preview := backup.Diff(current, art.Sources)

	_, _ = fmt.Fprintf(out, "artifact: %s\n", artifactPath)
	_, _ = fmt.Fprintf(out, "from:     %s at %s (tui-router %s)\n",
		art.Manifest.Hostname, art.Manifest.Timestamp, art.Manifest.ToolVersion)
	_, _ = fmt.Fprintf(out, "integrity: checksums verified\n")
	_, _ = fmt.Fprintf(out, "signature: %s\n", signatureStatus(art, verifier != nil))
	_, _ = fmt.Fprintf(out, "\nPreview (what a restore would apply):\n%s\n", preview.String())
	_, _ = fmt.Fprintf(out, "\nThen these commands run, in order ('!' may drop your session):\n%s\n",
		reloadPlanBlock(backend.ReloadPlan(art.Sources)))
	_, _ = fmt.Fprintln(out, "\nFinally the nftables ruleset is applied as one atomic transaction,\n"+
		"with a keep-or-rollback confirmation.")

	warning := deviceWarning(ctx, backend, art.Sources)
	if warning != "" {
		_, _ = fmt.Fprintf(out, "\nWARNING — the hardware does not match:\n%s\n", warning)
	}

	if dryRun {
		_, _ = fmt.Fprintln(out, "\n--dry-run: nothing was applied.")
		return nil
	}
	if !preview.HasChanges() {
		_, _ = fmt.Fprintln(out, "\nThe machine already matches the artifact; nothing to apply.")
		return nil
	}

	reader := bufio.NewReader(in)
	if warning != "" {
		// A hardware mismatch is its own decision, taken before the ordinary
		// apply confirmation: the operator says out loud that they mean to
		// restore onto different NICs.
		_, _ = fmt.Fprint(out, "\nRestore onto this different hardware anyway?\n"+
			"Type 'different hardware' to continue: ")
		answer, _ := reader.ReadString('\n')
		if strings.TrimSpace(answer) != "different hardware" {
			_, _ = fmt.Fprintln(out, "Aborted; nothing was applied.")
			return nil
		}
	}

	_, _ = fmt.Fprint(out, "\nApply these changes? This will write config, reload the services\n"+
		"above and reload the ruleset.\nType 'yes' to continue: ")
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		_, _ = fmt.Fprintln(out, "Aborted; nothing was applied.")
		return nil
	}

	// --keep answers the connectivity question up front, for a restore nobody
	// is sitting in front of. Otherwise the operator answers it live, on the
	// same reader the confirmations above were read from — a second reader
	// over the same stream would find the buffered bytes already gone, which
	// is exactly how a piped `keep` used to be lost.
	keep := interactiveKeepConfirm(reader, out, backup.DefaultKeepTimeout)
	if keepRuleset {
		keep = preConfirmedKeep(out)
	}
	return applyRestore(ctx, backend, art.Sources, backup.DefaultKeepTimeout, keep, out)
}

// applyRestore writes the artifact's state to the machine: the config-file
// subsystems first, then the nftables ruleset last through the connectivity-safe
// keep/rollback flow, because a bad ruleset is what locks an operator out. It is
// the single apply engine both the command and the round-trip test drive.
func applyRestore(ctx context.Context, backend router.BackupBackend, target backup.Sources,
	keepTimeout time.Duration, keep keepConfirmFunc, out io.Writer) error {

	// The single-file subsystems, in the order a router is built up: what the
	// machine is for (roles.conf), then how it forwards and resolves, then the
	// services that serve the LAN and the firewall tool's own saved ruleset.
	for _, single := range []struct{ subsystem, label, content string }{
		{backup.SubsystemRoles, "roles.conf", target.Roles},
		{backup.SubsystemSysctl, "sysctl drop-in", target.Sysctl},
		{backup.SubsystemResolved, "resolved drop-in", target.Resolved},
		{backup.SubsystemFirewallRules, "tui-firewall saved ruleset", target.FirewallRules},
	} {
		if strings.TrimSpace(single.content) == "" {
			continue
		}
		if err := backend.WriteConfig(ctx, single.subsystem, "", single.content); err != nil {
			return fmt.Errorf("writing the %s: %w", single.label, err)
		}
		_, _ = fmt.Fprintf(out, "  wrote %s\n", single.label)
	}

	for _, name := range sortedKeys(target.Networkd) {
		if err := backend.WriteConfig(ctx, backup.SubsystemNetworkd, name, target.Networkd[name]); err != nil {
			return fmt.Errorf("writing networkd unit %s: %w", name, err)
		}
		_, _ = fmt.Fprintf(out, "  wrote networkd/%s\n", name)
	}
	if strings.TrimSpace(target.DHCPDNS) != "" {
		if err := backend.WriteConfig(ctx, backup.SubsystemDHCPDNS, "", target.DHCPDNS); err != nil {
			return fmt.Errorf("writing dhcp-dns config: %w", err)
		}
		_, _ = fmt.Fprintln(out, "  wrote dhcp-dns config")
	}
	for _, name := range sortedWGKeys(target.Wireguard) {
		if err := backend.WriteConfig(ctx, backup.SubsystemWireguard, name, target.Wireguard[name].Config); err != nil {
			return fmt.Errorf("writing wireguard config %s: %w", name, err)
		}
		_, _ = fmt.Fprintf(out, "  wrote wireguard/%s (key material restored out of band)\n", name)
	}
	if len(target.Accounts) > 0 {
		if err := backend.ApplyAccounts(ctx, target.Accounts); err != nil {
			return fmt.Errorf("provisioning accounts: %w", err)
		}
		_, _ = fmt.Fprintf(out, "  ensured %d account(s), no credential set\n", len(target.Accounts))
	}

	// A file on disk changes nothing until something re-reads it, so the
	// restore reloads what it just wrote — the same previewed commands the
	// confirm showed, in the same order.
	if err := runReloads(ctx, backend, target, out); err != nil {
		return err
	}

	if strings.TrimSpace(target.Nftables) == "" {
		return nil
	}
	return applyNftables(ctx, backend, target.Nftables, keepTimeout, keep, out)
}

// runReloads runs the backend's reload plan. A step that fails is reported and
// the rest still run: half a restore that reloaded nothing is worse than one
// that reloaded what it could and said which step did not take.
func runReloads(ctx context.Context, backend router.BackupBackend,
	target backup.Sources, out io.Writer) error {

	steps := backend.ReloadPlan(target)
	if len(steps) == 0 {
		return nil
	}
	var failed []string
	for _, step := range steps {
		if err := backend.RunReload(ctx, step); err != nil {
			failed = append(failed, step.String())
			_, _ = fmt.Fprintf(out, "  reload FAILED: %s (%v)\n", step.String(), err)
			continue
		}
		_, _ = fmt.Fprintf(out, "  reloaded: %s\n", step.String())
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d reload step(s) failed: %s", len(failed), strings.Join(failed, "; "))
	}
	return nil
}

// reloadPlanBlock renders the reload plan for the restore preview: the exact
// commands, in order, that will run once the config files land.
func reloadPlanBlock(steps []router.ReloadStep) string {
	if len(steps) == 0 {
		return "  (nothing to reload — the artifact carries no config file that needs one)"
	}
	var b strings.Builder
	for _, step := range steps {
		mark := " "
		if step.Destructive {
			mark = "!"
		}
		fmt.Fprintf(&b, "  %s $ %s\n", mark, step.String())
	}
	return strings.TrimRight(b.String(), "\n")
}

// deviceWarning reports the interface names an artifact's roles.conf assigns
// that this machine does not have, as the block the extra confirmation shows.
// It returns "" when every named device is present, and says so plainly when
// the machine's own interface list could not be read.
func deviceWarning(ctx context.Context, backend router.BackupBackend, target backup.Sources) string {
	if strings.TrimSpace(target.Roles) == "" {
		return ""
	}
	present, err := backend.LinkNames(ctx)
	if err != nil {
		return "This machine's interface list could not be read (" + err.Error() + "),\n" +
			"so the artifact's WAN/LAN device names could not be checked against it."
	}
	missing := router.MissingRoleDevices(target.Roles, present)
	if len(missing) == 0 {
		return ""
	}
	return "The artifact assigns roles to " + strings.Join(missing, ", ") +
		",\nwhich this machine does not have (it has: " + strings.Join(present, ", ") + ").\n" +
		"Restoring as-is leaves those roles pointing at ports that do not exist,\n" +
		"and the router forwards nothing until you re-run the roles wizard."
}

// applyNftables installs the ruleset atomically, then either keeps it on the
// operator's confirmation or rolls back to the snapshot taken first.
func applyNftables(ctx context.Context, backend router.BackupBackend, ruleset string,
	keepTimeout time.Duration, keep keepConfirmFunc, out io.Writer) error {

	snapshot, err := backend.NftablesSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("snapshotting the current ruleset: %w", err)
	}
	session := backup.NewKeepSession(ruleset, snapshot, keepTimeout)
	if err := backend.ApplyNftables(ctx, session.ApplyPayload()); err != nil {
		return fmt.Errorf("applying the ruleset: %w", err)
	}
	// Arm with a nil callback: the command drives the keep countdown itself
	// below, so the session gives us the Awaiting phase and the rollback path.
	_ = session.Arm(nil)
	_, _ = fmt.Fprintln(out, "  applied the nftables ruleset atomically")

	if keep != nil && keep() {
		_ = session.Commit()
		_, _ = fmt.Fprintln(out, "  ruleset kept (connectivity confirmed)")
		return nil
	}
	if err := backend.ApplyNftables(ctx, session.RollbackPayload()); err != nil {
		return fmt.Errorf("rolling back the ruleset: %w", err)
	}
	_ = session.Rollback()
	_, _ = fmt.Fprintln(out, "  ruleset rolled back to the pre-restore snapshot")
	return errors.New("restore rolled back: connectivity was not confirmed after the ruleset applied")
}

// interactiveKeepConfirm builds the keep confirmation the command uses: after
// the ruleset applies, the operator has keepTimeout to type 'keep'; silence or
// anything else rolls back, which is what saves an operator who just cut their
// own session.
//
// It reads from the reader the earlier confirmations used rather than opening
// its own over the same stream. A bufio.Reader buffers ahead, so a second one
// wrapping the same pipe finds nothing left: that is what silently swallowed
// the `keep` line of a `printf 'yes\nkeep\n' | tui-router restore` and rolled
// every scripted restore back.
func interactiveKeepConfirm(reader *bufio.Reader, out io.Writer, keepTimeout time.Duration) keepConfirmFunc {
	return func() bool {
		_, _ = fmt.Fprintf(out, "\n  The new ruleset is live. Type 'keep' within %s to keep it,\n"+
			"  or the ruleset rolls back automatically: ", keepTimeout)
		answerCh := make(chan string, 1)
		go func() {
			line, _ := reader.ReadString('\n')
			answerCh <- strings.TrimSpace(line)
		}()
		select {
		case answer := <-answerCh:
			return answer == "keep"
		case <-time.After(keepTimeout):
			_, _ = fmt.Fprintln(out, "\n  (timed out)")
			return false
		}
	}
}

// preConfirmedKeep is --keep: the operator said before the restore started
// that the ruleset is to stay. It skips the keep window entirely rather than
// answering it, and says on the way past that the guard is not in force — a
// restore that silently dropped the safety net would be worse than one that
// never had it.
func preConfirmedKeep(out io.Writer) keepConfirmFunc {
	return func() bool {
		_, _ = fmt.Fprintln(out, "\n  --keep: keeping the ruleset without the connectivity"+
			" confirmation.\n  The rollback guard is not in force for this restore.")
		return true
	}
}

// loadSigner reads an Ed25519 key file and builds a Signer. The file may hold
// base64 (the common case) or raw bytes; either way, only the file is read and
// no secret is ever written back.
func loadSigner(path string) (backup.Signer, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the key path is an explicit CLI argument
	if err != nil {
		return nil, fmt.Errorf("reading the signing key: %w", err)
	}
	return backup.NewEd25519Signer(decodeKeyMaterial(raw), "")
}

// loadVerifier reads an Ed25519 public key file and builds a Verifier.
func loadVerifier(path string) (backup.Verifier, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // the key path is an explicit CLI argument
	if err != nil {
		return nil, fmt.Errorf("reading the public key: %w", err)
	}
	return backup.NewEd25519Verifier(decodeKeyMaterial(raw))
}

// decodeKeyMaterial accepts a base64 key file or a raw one: it tries to decode
// the trimmed text as base64 and falls back to the bytes as they are.
func decodeKeyMaterial(raw []byte) []byte {
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw))); err == nil {
		return decoded
	}
	return raw
}

// signatureStatus renders the signature line of the restore preview.
func signatureStatus(art *backup.Artifact, verifierGiven bool) string {
	switch {
	case art.SignatureVerified:
		return "present and verified against the given public key"
	case art.Signed && !verifierGiven:
		return "present but not checked (no --verify public key given)"
	case art.Signed:
		return "present"
	default:
		return "none (integrity still verified by checksums)"
	}
}

// defaultArtifactName builds the default output filename from the host and the
// stamp the CLI layer passed in.
func defaultArtifactName(host, stamp string) string {
	host = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == ' ' {
			return '-'
		}
		return r
	}, host)
	return fmt.Sprintf("router-%s-%s%s", host, stamp, backup.Extension)
}

// sortedKeys and sortedWGKeys mirror the pure package's stable ordering so the
// apply loop touches subsystems in a deterministic order.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

func sortedWGKeys(m map[string]backup.WGConf) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// sortStrings is a tiny insertion sort, kept local so this file needs no import
// for the two short key slices it orders.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// flagPassed reports whether a flag was set on the command line, so `--sudo ""`
// disables escalation instead of reading as "not given".
func flagPassed(fs *flag.FlagSet, name string) bool {
	passed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}
