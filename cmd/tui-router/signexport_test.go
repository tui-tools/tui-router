package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// onMachine points export and restore at a key directory of their own, the
// stand-in for one machine's /etc/tui-router. Two calls are two machines.
func onMachine(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc-tui-router")
	store := router.NewDirKeyStore(dir, nil)
	previous := keyStoreFor
	keyStoreFor = func(router.BackupBackend) router.KeyStore { return store }
	t.Cleanup(func() { keyStoreFor = previous })
	return dir
}

// exportDefault runs a plain `tui-router export --demo`, answering the key
// question with answer.
func exportDefault(t *testing.T, artifact, answer string, extra ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	args := append([]string{"--demo", "--out", artifact}, extra...)
	err := runExport(args, "stamp", strings.NewReader(answer), &out)
	return out.String(), err
}

// restoreDemo runs a restore of artifact into the demo router, confirming and
// keeping the ruleset.
func restoreDemo(t *testing.T, artifact string, extra ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	args := append(append([]string{"--demo"}, extra...), artifact)
	err := runRestore(args, strings.NewReader("yes\nkeep\n"), &out)
	return out.String(), err
}

// TestFirstExportCreatesTheKeyAndSigns: on a machine without a key, a plain
// export previews the creation, asks, creates it with the right modes, signs,
// and writes the public key beside the artifact with its fingerprint.
func TestFirstExportCreatesTheKeyAndSigns(t *testing.T) {
	dir := onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")

	out, err := exportDefault(t, artifact, "yes\n")
	if err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	for _, want := range []string{
		"no backup signing key yet",
		"$ install -m 0600 /dev/stdin " + dir + "/backup-signing.key",
		"Type 'yes'",
		"signed: yes",
		"public key: " + artifact + ".pub  SHA256:",
		"somewhere other than the backup",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("export output lacks %q:\n%s", want, out)
		}
	}
	if got := fileMode(t, filepath.Join(dir, router.SigningKeyName)); got != 0o600 {
		t.Errorf("private key mode = %04o", got)
	}
	if got := fileMode(t, filepath.Join(dir, router.SigningPubName)); got != 0o644 {
		t.Errorf("public key mode = %04o", got)
	}

	art := openArtifact(t, artifact)
	if !art.Signed {
		t.Fatal("the artifact is not signed")
	}
	// The .pub beside it is the machine's public key.
	machinePub := readFileT(t, filepath.Join(dir, router.SigningPubName))
	if besidePub := readFileT(t, artifact+".pub"); besidePub != machinePub {
		t.Errorf("beside .pub = %q, machine key = %q", besidePub, machinePub)
	}

	// The second export signs with the same key and asks nothing.
	second := filepath.Join(t.TempDir(), "r2.tuiback")
	out, err = exportDefault(t, second, "")
	if err != nil || strings.Contains(out, "no backup signing key yet") || !strings.Contains(out, "signed: yes") {
		t.Fatalf("second export: %v\n%s", err, out)
	}
	if readFileT(t, second+".pub") != machinePub {
		t.Errorf("the second export used another key")
	}
}

// TestDecliningTheKeyExportsNothing: without a yes (or --create-key) no key is
// created and no artifact is written.
func TestDecliningTheKeyExportsNothing(t *testing.T) {
	dir := onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	out, err := exportDefault(t, artifact, "")
	if err == nil || !strings.Contains(err.Error(), "--no-sign") {
		t.Fatalf("err = %v\n%s", err, out)
	}
	for _, path := range []string{artifact, filepath.Join(dir, router.SigningKeyName)} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s was written", path)
		}
	}

	// --create-key answers the question up front, for a scripted export.
	out, err = exportDefault(t, artifact, "", "--create-key")
	if err != nil || !strings.Contains(out, "signed: yes") || strings.Contains(out, "Type 'yes'") {
		t.Fatalf("--create-key: %v\n%s", err, out)
	}
}

// TestSameMachineRestoreVerifiesWithNoFlags is the point of the change: a
// backup restored where it was taken verifies against the machine's own key.
func TestSameMachineRestoreVerifiesWithNoFlags(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	out, err := restoreDemo(t, artifact)
	if err != nil {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "verified against this machine's trusted key") ||
		strings.Contains(out, "TRUSTING") {
		t.Errorf("same-machine restore:\n%s", out)
	}
}

// TestAnotherMachineNeedsTheKeyFromElsewhere: on a machine without the
// exporting key the restore is refused by default — the .pub travelling with
// the artifact is not trusted on its own — and it works with --verify, or with
// the key placed in trusted-keys.
func TestAnotherMachineNeedsTheKeyFromElsewhere(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	// The operator's own copy of the public key, kept apart from the backup.
	recorded := filepath.Join(t.TempDir(), "router-a.pub")
	writeFile(t, recorded, readFileT(t, artifact+".pub"))

	rebuilt := onMachine(t)
	out, err := restoreDemo(t, artifact)
	if err == nil || !strings.Contains(err.Error(), "restore refused") {
		t.Fatalf("another machine restored it with no key:\n%s", out)
	}
	if !strings.Contains(err.Error(), artifact+".pub sits beside the artifact") ||
		!strings.Contains(err.Error(), "not trusted on its own") {
		t.Errorf("the refusal does not explain the .pub beside it: %v", err)
	}

	out, err = restoreDemo(t, artifact, "--verify", recorded)
	if err != nil || !strings.Contains(out, "verified against the given public key "+recorded) {
		t.Fatalf("--verify: %v\n%s", err, out)
	}

	trusted := filepath.Join(rebuilt, router.TrustedKeysName)
	if err := os.MkdirAll(trusted, 0o755); err != nil { //nolint:gosec // the real directory's mode
		t.Fatal(err)
	}
	pubFile := filepath.Join(trusted, "router-a.pub")
	if err := os.WriteFile(pubFile, []byte(readFileT(t, recorded)), 0o644); err != nil { //nolint:gosec // a public key is meant to be read
		t.Fatal(err)
	}
	out, err = restoreDemo(t, artifact)
	if err != nil || !strings.Contains(out, "trusted key "+filepath.Join(trusted, "router-a.pub")) {
		t.Fatalf("trusted-keys: %v\n%s", err, out)
	}
}

// TestSignedArtifactTamperedFails: a changed byte fails whatever key would
// have verified it.
func TestSignedArtifactTamperedFails(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	data := []byte(readFileT(t, artifact))
	data[len(data)/2] ^= 0x40
	writeRawFile(t, artifact, data)
	if out, err := restoreDemo(t, artifact); err == nil {
		t.Fatalf("a tampered artifact was restored:\n%s", out)
	}
	if out, err := restoreDemo(t, artifact, "--verify", artifact+".pub"); err == nil {
		t.Fatalf("a tampered artifact verified:\n%s", out)
	}
}

// TestReSignedArtifactWithItsOwnPubIsNotTrusted is the attack the .pub rule
// exists for: whoever can change the backup re-signs it with their own key and
// replaces the .pub beside it. The machine trusts neither.
func TestReSignedArtifactWithItsOwnPubIsNotTrusted(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	attacker, attackerPub := signingPair(t)
	forged := artifactFile(t, backup.Sources{Nftables: trustRuleset}, attacker)
	writeFile(t, forged+".pub", readFileT(t, attackerPub))

	out, err := restoreDemo(t, forged)
	if err == nil || strings.Contains(out, "applied") {
		t.Fatalf("a forged artifact with its own .pub was restored:\n%s", out)
	}
}

// TestNoSignWritesAnUnsignedArtifact: --no-sign means no signature, no .pub
// and no key created.
func TestNoSignWritesAnUnsignedArtifact(t *testing.T) {
	dir := onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	out, err := exportDefault(t, artifact, "", "--no-sign")
	if err != nil || !strings.Contains(out, "signed: no") {
		t.Fatalf("export --no-sign: %v\n%s", err, out)
	}
	if openArtifact(t, artifact).Signed {
		t.Error("--no-sign produced a signed artifact")
	}
	for _, path := range []string{artifact + ".pub", filepath.Join(dir, router.SigningKeyName)} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("%s was written", path)
		}
	}
	if _, err := exportDefault(t, artifact, "", "--no-sign", "--sign", "k"); err == nil ||
		!strings.Contains(err.Error(), "contradict") {
		t.Errorf("--sign with --no-sign: %v", err)
	}
}

// TestCockpitExportCreatesTheKeyThenSigns: the export plan shows the creation
// steps; y runs them and writes a signed artifact with its .pub.
func TestCockpitExportCreatesTheKeyThenSigns(t *testing.T) {
	dir := onMachine(t)
	artifact := filepath.Join(t.TempDir(), "c.tuiback")
	s := newBackupScreen(router.NewFake())
	stepScreen(t, s, keyRunes("e"))
	s.input.Model.SetValue(artifact)
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsExportPlan || s.keyPlan == nil {
		t.Fatalf("step = %v, key plan %v (%s)", s.step, s.keyPlan, s.failed)
	}
	view := s.View(theme.New(), 160, 80)
	for _, want := range []string{"no signing key yet", "install -m 0600 /dev/stdin " + dir,
		"create the key, then write it signed", "write it unsigned"} {
		if !strings.Contains(view, want) {
			t.Errorf("the plan lacks %q:\n%s", want, view)
		}
	}
	stepScreen(t, s, keyRunes("y"))
	if s.step != bsDone || s.failed != "" || !strings.Contains(s.output, "signed.") {
		t.Fatalf("step %v failed %q output %q", s.step, s.failed, s.output)
	}
	if !openArtifact(t, artifact).Signed {
		t.Error("the cockpit export is not signed")
	}
	if got := fileMode(t, filepath.Join(dir, router.SigningKeyName)); got != 0o600 {
		t.Errorf("private key mode = %04o", got)
	}

	// And the cockpit restore of it verifies with no question asked.
	s = newBackupScreen(router.NewFake())
	stepScreen(t, s, keyRunes("r"))
	s.input.Model.SetValue(artifact)
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsRestorePlan || !s.artifact.SignatureVerified {
		t.Fatalf("same-machine cockpit restore: step %v (%s)", s.step, s.failed)
	}
}

// TestCockpitOffersTheBesidePubOnlyAsADefault: on another machine the key
// prompt is prefilled with the .pub beside the artifact and shows its
// fingerprint; nothing was verified with it before the operator accepted it.
func TestCockpitOffersTheBesidePubOnlyAsADefault(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	onMachine(t)
	s := newBackupScreen(router.NewFake())
	stepScreen(t, s, keyRunes("r"))
	s.input.Model.SetValue(artifact)
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsVerifyKey {
		t.Fatalf("step = %v (%s)", s.step, s.failed)
	}
	key, _ := besideKey(artifact)
	if s.input.Value() != artifact+".pub" || !strings.Contains(s.input.Help, key.Fingerprint()) ||
		!strings.Contains(s.input.Help, "proves nothing by itself") {
		t.Errorf("prompt value %q help %q", s.input.Value(), s.input.Help)
	}
	if s.artifact != nil {
		t.Fatal("an artifact was accepted before the operator chose a key")
	}
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsRestorePlan || !s.artifact.SignatureVerified {
		t.Fatalf("step %v (%s)", s.step, s.failed)
	}
	if view := s.View(theme.New(), 160, 80); !strings.Contains(view, "only as good as your check") {
		t.Errorf("the plan does not qualify a key that sat beside the artifact:\n%s", view)
	}
}

func openArtifact(t *testing.T, path string) *backup.Artifact {
	t.Helper()
	art, err := backup.Open([]byte(readFileT(t, path)), nil)
	if err != nil {
		t.Fatal(err)
	}
	return art
}

func readFileT(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // a test tempdir file
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// TestTamperedUnderTheMachinesOwnKeySaysSo: an artifact whose checksums were
// recomputed after an edit still carries the SIGNATURE the machine made, naming
// the machine's own key. The refusal must not claim the artifact was signed by
// some other key — it was signed by this one, and then changed.
func TestTamperedUnderTheMachinesOwnKeySaysSo(t *testing.T) {
	onMachine(t)
	artifact := filepath.Join(t.TempDir(), "r.tuiback")
	if out, err := exportDefault(t, artifact, "yes\n"); err != nil {
		t.Fatalf("export: %v\n%s", err, out)
	}
	// Different content, consistent checksums, the machine's signature grafted on.
	edited := artifactFile(t, backup.Sources{Nftables: trustRuleset}, nil)
	tampered := filepath.Join(t.TempDir(), "t.tuiback")
	graftSignature(t, artifact, edited, tampered)

	out, err := restoreDemo(t, tampered)
	if err == nil {
		t.Fatalf("a tampered artifact was restored:\n%s", out)
	}
	if strings.Contains(err.Error(), "not by this machine's key") {
		t.Errorf("the refusal blames another key for the machine's own signature: %v", err)
	}
	if !strings.Contains(err.Error(), "changed after it was signed") {
		t.Errorf("the refusal does not say the artifact changed after signing: %v", err)
	}

	var dry bytes.Buffer
	if err := runRestore([]string{"--demo", "--dry-run", tampered}, strings.NewReader(""), &dry); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, dry.String())
	}
	if !strings.Contains(dry.String(), "changed after it was signed") {
		t.Errorf("the preview's signature line does not say so:\n%s", dry.String())
	}
}

// graftSignature writes dst: the parts of onto, with the SIGNATURE of from.
func graftSignature(t *testing.T, from, onto, dst string) {
	t.Helper()
	signature := tarEntries(t, from)["SIGNATURE"]
	if signature == nil {
		t.Fatal("the source artifact has no SIGNATURE")
	}
	entries := tarEntries(t, onto)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range append(names, "SIGNATURE") {
		body := entries[name]
		if name == "SIGNATURE" {
			body = signature
		}
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	writeRawFile(t, dst, buf.Bytes())
}

// tarEntries reads every regular file of a .tuiback.
func tarEntries(t *testing.T, path string) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(strings.NewReader(readFileT(t, path)))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	entries := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries[hdr.Name] = body
	}
}
