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
	parts := len(src.Networkd) + len(src.Wireguard)
	if strings.TrimSpace(src.Nftables) != "" {
		parts++
	}
	if strings.TrimSpace(src.DHCPDNS) != "" {
		parts++
	}
	if len(src.Accounts) > 0 {
		parts++
	}
	_, _ = fmt.Fprintf(out, "wrote %s — %d parts, %d bytes, signed: %s\n",
		outPath, parts, len(data), signed)
	return nil
}

// runRestore opens an artifact, previews it, and — outside --dry-run and after
// one explicit confirmation — applies it with a connectivity-safe rollback.
func runRestore(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	fs.SetOutput(out)
	var verifyKey, sudo string
	var dryRun, demo bool
	fs.StringVar(&verifyKey, "verify", "", "require a valid signature from the Ed25519 public key in this file")
	fs.BoolVar(&dryRun, "dry-run", false, "verify and preview only; apply nothing")
	fs.BoolVar(&demo, "demo", false, "restore into the in-memory sample router, no root needed")
	fs.StringVar(&sudo, "sudo", "", "privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-router restore FILE [--verify PUBKEY] [--dry-run] [--demo]\n\n"+
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

	if dryRun {
		_, _ = fmt.Fprintln(out, "\n--dry-run: nothing was applied.")
		return nil
	}
	if !preview.HasChanges() {
		_, _ = fmt.Fprintln(out, "\nThe machine already matches the artifact; nothing to apply.")
		return nil
	}

	_, _ = fmt.Fprint(out, "\nApply these changes? This will write config and reload the ruleset.\n"+
		"Type 'yes' to continue: ")
	reader := bufio.NewReader(in)
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(answer) != "yes" {
		_, _ = fmt.Fprintln(out, "Aborted; nothing was applied.")
		return nil
	}

	keep := interactiveKeepConfirm(in, out, backup.DefaultKeepTimeout)
	return applyRestore(ctx, backend, art.Sources, backup.DefaultKeepTimeout, keep, out)
}

// applyRestore writes the artifact's state to the machine: the config-file
// subsystems first, then the nftables ruleset last through the connectivity-safe
// keep/rollback flow, because a bad ruleset is what locks an operator out. It is
// the single apply engine both the command and the round-trip test drive.
func applyRestore(ctx context.Context, backend router.BackupBackend, target backup.Sources,
	keepTimeout time.Duration, keep keepConfirmFunc, out io.Writer) error {

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

	if strings.TrimSpace(target.Nftables) == "" {
		return nil
	}
	return applyNftables(ctx, backend, target.Nftables, keepTimeout, keep, out)
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
func interactiveKeepConfirm(in io.Reader, out io.Writer, keepTimeout time.Duration) keepConfirmFunc {
	return func() bool {
		_, _ = fmt.Fprintf(out, "\n  The new ruleset is live. Type 'keep' within %s to keep it,\n"+
			"  or the ruleset rolls back automatically: ", keepTimeout)
		answerCh := make(chan string, 1)
		go func() {
			line, _ := bufio.NewReader(in).ReadString('\n')
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
