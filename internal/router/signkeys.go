package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-router/internal/backup"
)

// The machine's backup signing keys. They live beside the tool's system
// configuration (/etc/tui-router/config.toml), the way sshd keeps its host keys
// in /etc/ssh: a key pair that identifies this machine, created once.
const (
	// SigningKeyDir holds the key pair and the trusted-keys directory.
	SigningKeyDir = "/etc/tui-router"
	// SigningKeyName is the private key: base64 of the 32-byte Ed25519 seed,
	// root-only (0600). It never leaves the machine and is never printed.
	SigningKeyName = "backup-signing.key"
	// SigningPubName is its public half, world-readable (0644).
	SigningPubName = "backup-signing.pub"
	// TrustedKeysName is the directory an operator places other machines'
	// public keys in (*.pub), so their artifacts restore here without --verify.
	TrustedKeysName = "trusted-keys"

	signingKeyMode = "0600"
	signingPubMode = "0644"
	keyDirMode     = "0755"
)

// ErrNoSigningKey is what LocalSigner returns on a machine that has never
// exported with its own key: the first export creates one.
var ErrNoSigningKey = errors.New("this machine has no backup signing key yet")

// TrustedKey is a public key a restore accepts a signature from without being
// told which key to use: the machine's own, or one an operator placed in the
// trusted-keys directory.
type TrustedKey struct {
	// Path is the file the key was read from.
	Path string
	// Public is the key itself.
	Public ed25519.PublicKey
}

// Fingerprint is the key's SHA256 fingerprint, as export printed it.
func (k TrustedKey) Fingerprint() string { return backup.Fingerprint(k.Public) }

// KeyStep is one previewed command of the key creation. Preview is rendered
// from Command by the runner that will run it, so the two cannot drift.
type KeyStep struct {
	Command runner.Command
	Preview string
}

// KeyCreation is a key pair generated in memory and the steps that would store
// it. Nothing is on disk until Create runs the steps the operator was shown.
type KeyCreation struct {
	// Public is the new key's public half, so the plan can show its
	// fingerprint before anything is written.
	Public ed25519.PublicKey
	// Steps are run in order.
	Steps []KeyStep
	// seed is the private key, held only in this value and in the stdin of
	// the step that writes it.
	seed []byte
}

// KeyStore is where export finds the machine's signing key and restore finds
// the keys it trusts. The real one is a directory under /etc; the demo's is in
// memory, so --demo never writes a key anywhere.
type KeyStore interface {
	// Location names the directory, for messages.
	Location() string
	// TrustedDir is the directory of other machines' public keys.
	TrustedDir() string
	// LocalSigner returns the machine's signing key, or ErrNoSigningKey.
	LocalSigner(ctx context.Context) (backup.Signer, error)
	// PlanCreate generates a key pair and returns the steps that store it. It
	// refuses when a key already exists: a machine's key is never replaced
	// behind the operator's back, because every backup signed with the old
	// one would stop verifying.
	PlanCreate() (*KeyCreation, error)
	// Create runs the plan's steps and returns the signer for the new key.
	Create(ctx context.Context, plan *KeyCreation) (backup.Signer, error)
	// Trusted returns the keys a restore accepts without --verify: the
	// machine's own public key first, then trusted-keys/*.pub in name order.
	// problems names every file that was skipped, and why.
	Trusted() (keys []TrustedKey, problems []string)
}

// DirKeyStore is the real KeyStore: a directory root owns.
type DirKeyStore struct {
	dir string
	// install writes the key files through the privilege prefix. nil when
	// install(1) is missing, which Create reports.
	install *runner.Runner
	// cat reads the private key through the privilege prefix when this
	// process cannot open it itself. nil when there is no prefix.
	cat *runner.Runner
}

// NewDirKeyStore builds the store over dir. sudoPrefix is the configured
// escalation, nil to run install and read the key directly.
func NewDirKeyStore(dir string, sudoPrefix []string) *DirKeyStore {
	store := &DirKeyStore{dir: dir}
	store.install, _ = runner.New(runner.Options{
		Bin: "install", SearchPaths: []string{"/usr/bin/install", "/bin/install"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	if len(sudoPrefix) > 0 {
		store.cat, _ = runner.New(runner.Options{
			Bin: "cat", SearchPaths: []string{"/usr/bin/cat", "/bin/cat"},
			SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
		})
	}
	return store
}

// Location is the store's directory.
func (s *DirKeyStore) Location() string { return s.dir }

// TrustedDir is the trusted-keys directory.
func (s *DirKeyStore) TrustedDir() string { return s.trustedPath() }

func (s *DirKeyStore) keyPath() string     { return filepath.Join(s.dir, SigningKeyName) }
func (s *DirKeyStore) pubPath() string     { return filepath.Join(s.dir, SigningPubName) }
func (s *DirKeyStore) trustedPath() string { return filepath.Join(s.dir, TrustedKeysName) }

// LocalSigner reads the machine's signing key. The file is held to what a
// private key file must be — a regular file, owned by root (or by this
// process's user, which is root in production), readable by nobody else —
// and its public half must match the .pub beside it, or the two trust anchors
// would disagree about which key this machine signs with.
func (s *DirKeyStore) LocalSigner(ctx context.Context) (backup.Signer, error) {
	path := s.keyPath()
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoSigningKey
	}
	if err != nil {
		return nil, fmt.Errorf("checking %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; refusing to sign with it", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %04o: a private key must be readable by root only "+
			"(chmod %s %s)", path, info.Mode().Perm(), signingKeyMode, path)
	}
	if !ownedByRootOrMe(info) {
		return nil, fmt.Errorf("%s is not owned by root; refusing to sign with it", path)
	}

	raw, err := os.ReadFile(path) //nolint:gosec // a fixed path under the tool's own key directory
	if os.IsPermission(err) && s.cat != nil {
		var out string
		out, err = s.cat.Read(ctx, "cat", "--", path)
		raw = []byte(out)
	}
	if err != nil {
		return nil, fmt.Errorf("reading the signing key %s: %w (export as root)", path, err)
	}
	signer, err := backup.NewEd25519Signer(backup.DecodeKeyMaterial(raw), "")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, err := readTrustedKey(s.pubPath())
	if err != nil {
		return nil, fmt.Errorf("the machine's public key: %w", err)
	}
	if !pub.Public.Equal(signer.Public()) {
		return nil, fmt.Errorf("%s does not match %s; refusing to sign until they agree",
			s.pubPath(), path)
	}
	return backup.NewEd25519Signer(backup.DecodeKeyMaterial(raw), pub.Fingerprint())
}

// PlanCreate generates the key pair and the steps that store it.
func (s *DirKeyStore) PlanCreate() (*KeyCreation, error) {
	if _, err := os.Lstat(s.keyPath()); !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s already exists; it is not replaced", s.keyPath())
	}
	plan, err := newKeyCreation(s.dir, dirMissing(s.dir), dirMissing(s.trustedPath()))
	if err != nil {
		return nil, err
	}
	for i := range plan.Steps {
		plan.Steps[i].Preview = s.preview(plan.Steps[i].Command)
	}
	return plan, nil
}

// preview renders a step the way it will run.
func (s *DirKeyStore) preview(cmd runner.Command) string {
	if s.install == nil {
		return cmd.String()
	}
	return s.install.Preview(cmd)
}

// Create runs the steps the operator confirmed and returns the new key's
// signer. It checks again that no key appeared in the meantime: install(1)
// would replace one, and a replaced key orphans every backup it signed.
func (s *DirKeyStore) Create(ctx context.Context, plan *KeyCreation) (backup.Signer, error) {
	if plan == nil {
		return nil, errors.New("no key creation was planned")
	}
	if s.install == nil {
		return nil, errors.New("install(1) is not available to store the signing key")
	}
	if _, err := os.Lstat(s.keyPath()); !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s appeared since the plan was shown; nothing was written", s.keyPath())
	}
	for _, step := range plan.Steps {
		if _, err := s.install.Run(ctx, step.Command); err != nil {
			return nil, err
		}
	}
	return plan.signer()
}

// Trusted reads the machine's public key and the trusted-keys directory.
func (s *DirKeyStore) Trusted() ([]TrustedKey, []string) {
	var keys []TrustedKey
	var problems []string
	if local, err := readTrustedKey(s.pubPath()); err == nil {
		keys = append(keys, local)
	} else if !errors.Is(err, fs.ErrNotExist) {
		problems = append(problems, err.Error())
	}

	dir := s.trustedPath()
	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return keys, problems
	case err != nil:
		return keys, append(problems, err.Error())
	case !info.IsDir():
		return keys, append(problems, dir+" is not a directory")
	case !anchorSafe(info):
		// Whoever can add a file here can make any artifact verify.
		return keys, append(problems, dir+" is writable by someone other than root; "+
			"none of its keys are trusted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return keys, append(problems, err.Error())
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".pub") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		key, err := readTrustedKey(filepath.Join(dir, name))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		keys = append(keys, key)
	}
	return keys, problems
}

// readTrustedKey reads one public key file a restore would trust. Trust is
// only as good as the file's protection, so one somebody other than root
// could have written is skipped rather than believed.
func readTrustedKey(path string) (TrustedKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return TrustedKey{}, err
	}
	if !info.Mode().IsRegular() {
		return TrustedKey{}, fmt.Errorf("%s is not a regular file", path)
	}
	if !anchorSafe(info) {
		return TrustedKey{}, fmt.Errorf("%s is writable by someone other than root; not trusted", path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // a key file under the tool's own key directory
	if err != nil {
		return TrustedKey{}, err
	}
	pub, err := backup.ParsePublicKey(raw)
	if err != nil {
		return TrustedKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return TrustedKey{Path: path, Public: pub}, nil
}

// anchorSafe reports whether a trust anchor (a key file or the directory of
// them) can only have been written by root.
func anchorSafe(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0 && ownedByRootOrMe(info)
}

// ownedByRootOrMe accepts root's files, and this process's own: in production
// both are root, and a test runs as a plain user against its own directory.
func ownedByRootOrMe(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == 0 || int(stat.Uid) == os.Geteuid()
}

// dirMissing reports whether a directory has to be created.
func dirMissing(dir string) bool {
	_, err := os.Stat(dir)
	return errors.Is(err, fs.ErrNotExist)
}

// newKeyCreation generates a key pair and builds the install(1) steps that
// store it under dir. The private key goes through stdin, never the argv, so
// no preview, process listing or log can show it; install creates the file
// 0600 from the start rather than tightening it after the content landed.
func newKeyCreation(dir string, createDir, createTrusted bool) (*KeyCreation, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the signing key: %w", err)
	}
	plan := &KeyCreation{Public: pub, seed: priv.Seed()}
	add := func(cmd runner.Command) {
		plan.Steps = append(plan.Steps, KeyStep{Command: cmd, Preview: cmd.String()})
	}
	if createDir {
		add(runner.Command{
			Argv:        []string{"install", "-d", "-m", keyDirMode, dir},
			Description: "Create " + dir,
		})
	}
	add(runner.Command{
		Argv: []string{"install", "-m", signingKeyMode, "/dev/stdin",
			filepath.Join(dir, SigningKeyName)},
		Description: "Store the private signing key, readable by root only",
		Destructive: true,
		Stdin:       base64.StdEncoding.EncodeToString(plan.seed) + "\n",
	})
	add(runner.Command{
		Argv: []string{"install", "-m", signingPubMode, "/dev/stdin",
			filepath.Join(dir, SigningPubName)},
		Description: "Store its public key, which restore trusts on this machine",
		Destructive: true,
		Stdin:       string(backup.EncodePublicKey(pub)),
	})
	if createTrusted {
		add(runner.Command{
			Argv:        []string{"install", "-d", "-m", keyDirMode, filepath.Join(dir, TrustedKeysName)},
			Description: "Create the directory for other machines' public keys",
		})
	}
	return plan, nil
}

// signer is the plan's key as a Signer, named by its fingerprint.
func (p *KeyCreation) signer() (backup.Signer, error) {
	return backup.NewEd25519Signer(p.seed, backup.Fingerprint(p.Public))
}

// MemKeyStore is the demo's KeyStore: the same plan, previewed the same way and
// marked as the demo's, with the key held in memory for the life of the
// process. A demo restore in another process therefore finds no key, which is
// exactly what a rebuilt machine sees.
type MemKeyStore struct {
	signer backup.Signer
	public ed25519.PublicKey
}

// Location is where the real store would be.
func (m *MemKeyStore) Location() string { return SigningKeyDir + " (demo: in memory)" }

// TrustedDir is where the real store keeps other machines' keys.
func (m *MemKeyStore) TrustedDir() string { return SigningKeyDir + "/" + TrustedKeysName }

// LocalSigner returns the key Create made, if it ran.
func (m *MemKeyStore) LocalSigner(context.Context) (backup.Signer, error) {
	if m.signer == nil {
		return nil, ErrNoSigningKey
	}
	return m.signer, nil
}

// PlanCreate builds the real plan, marked as not run.
func (m *MemKeyStore) PlanCreate() (*KeyCreation, error) {
	if m.signer != nil {
		return nil, errors.New("the demo machine already has a signing key")
	}
	plan, err := newKeyCreation(SigningKeyDir, false, false)
	if err != nil {
		return nil, err
	}
	for i := range plan.Steps {
		plan.Steps[i].Preview += " (demo: not run)"
	}
	return plan, nil
}

// Create keeps the key in memory.
func (m *MemKeyStore) Create(_ context.Context, plan *KeyCreation) (backup.Signer, error) {
	if plan == nil {
		return nil, errors.New("no key creation was planned")
	}
	signer, err := plan.signer()
	if err != nil {
		return nil, err
	}
	m.signer, m.public = signer, plan.Public
	return signer, nil
}

// Trusted is the demo machine's own key, once it has one.
func (m *MemKeyStore) Trusted() ([]TrustedKey, []string) {
	if m.signer == nil {
		return nil, nil
	}
	return []TrustedKey{{Path: SigningKeyDir + "/" + SigningPubName + " (demo)", Public: m.public}}, nil
}
