package router

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tui-tools/tui-router/internal/backup"
)

// keyDir is a fresh directory standing in for /etc/tui-router. The store runs
// install(1) directly — no prefix — so the steps are the real commands and the
// modes on disk are the ones they set.
func keyDir(t *testing.T) (*DirKeyStore, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tui-router")
	return NewDirKeyStore(dir, nil), dir
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestFirstKeyIsCreatedByThePreviewedStepsWithTheRightModes(t *testing.T) {
	store, dir := keyDir(t)
	ctx := context.Background()
	if _, err := store.LocalSigner(ctx); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("a fresh machine: err = %v, want ErrNoSigningKey", err)
	}

	plan, err := store.PlanCreate()
	if err != nil {
		t.Fatal(err)
	}
	// Planning writes nothing.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("PlanCreate touched the disk: %v", err)
	}
	var previews []string
	for _, step := range plan.Steps {
		previews = append(previews, step.Preview)
		if step.Command.Argv[0] != "install" {
			t.Errorf("step %q is not install(1)", step.Preview)
		}
	}
	want := []string{
		"install -d -m 0755 " + dir,
		"install -m 0600 /dev/stdin " + dir + "/backup-signing.key",
		"install -m 0644 /dev/stdin " + dir + "/backup-signing.pub",
		"install -d -m 0755 " + dir + "/trusted-keys",
	}
	if strings.Join(previews, "\n") != strings.Join(want, "\n") {
		t.Errorf("steps:\n%s\nwant:\n%s", strings.Join(previews, "\n"), strings.Join(want, "\n"))
	}
	// The private key travels in stdin, never in what is shown.
	seed := plan.Steps[1].Command.Stdin
	for _, preview := range previews {
		if strings.Contains(preview, strings.TrimSpace(seed)) {
			t.Fatalf("a preview shows the private key: %s", preview)
		}
	}

	signer, err := store.Create(ctx, plan)
	if err != nil {
		t.Fatal(err)
	}
	if got := mode(t, filepath.Join(dir, SigningKeyName)); got != 0o600 {
		t.Errorf("private key mode = %04o, want 0600", got)
	}
	if got := mode(t, filepath.Join(dir, SigningPubName)); got != 0o644 {
		t.Errorf("public key mode = %04o, want 0644", got)
	}
	if got := mode(t, dir); got != 0o755 {
		t.Errorf("key directory mode = %04o, want 0755", got)
	}
	if !signer.Public().Equal(plan.Public) || signer.KeyID() != backup.Fingerprint(plan.Public) {
		t.Errorf("signer = %s, want the planned key", signer.KeyID())
	}

	// The next export finds it, and the machine trusts its public half.
	again, err := store.LocalSigner(ctx)
	if err != nil || !again.Public().Equal(plan.Public) {
		t.Fatalf("LocalSigner after create: %v", err)
	}
	keys, problems := store.Trusted()
	if len(problems) != 0 || len(keys) != 1 || !keys[0].Public.Equal(plan.Public) {
		t.Errorf("trusted = %+v, problems %v", keys, problems)
	}

	// A machine's key is never replaced.
	if _, err := store.PlanCreate(); err == nil {
		t.Errorf("PlanCreate planned over an existing key")
	}
	if _, err := store.Create(ctx, plan); err == nil {
		t.Errorf("Create ran over an existing key")
	}
}

func TestAPrivateKeyOthersCanReadIsRefused(t *testing.T) {
	store, dir := keyDir(t)
	ctx := context.Background()
	plan, err := store.PlanCreate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, SigningKeyName)
	if err := os.Chmod(key, 0o644); err != nil { //nolint:gosec // the mode under test
		t.Fatal(err)
	}
	if _, err := store.LocalSigner(ctx); err == nil || !strings.Contains(err.Error(), "0644") {
		t.Errorf("a world-readable key: err = %v", err)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}

	// A .pub that does not match the key is a disagreement, not a choice.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(filepath.Join(dir, SigningPubName), backup.EncodePublicKey(other), 0o644); err != nil { //nolint:gosec // a public key
		t.Fatal(err)
	}
	if _, err := store.LocalSigner(ctx); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("mismatched pub: err = %v", err)
	}
}

func TestTrustedKeysDirectory(t *testing.T) {
	store, dir := keyDir(t)
	trusted := filepath.Join(dir, TrustedKeysName)
	if err := os.MkdirAll(trusted, 0o755); err != nil { //nolint:gosec // mirrors the real directory's mode
		t.Fatal(err)
	}
	good, _, _ := ed25519.GenerateKey(rand.Reader)
	writable, _, _ := ed25519.GenerateKey(rand.Reader)
	write := func(name string, content []byte, perm os.FileMode) {
		path := filepath.Join(trusted, name)
		if err := os.WriteFile(path, content, perm); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
	}
	write("lab-router.pub", backup.EncodePublicKey(good), 0o644)
	write("loose.pub", backup.EncodePublicKey(writable), 0o666)
	write("broken.pub", []byte("not a key\n"), 0o644)
	write("notes.txt", []byte("ignored\n"), 0o644)

	keys, problems := store.Trusted()
	if len(keys) != 1 || !keys[0].Public.Equal(good) {
		t.Errorf("trusted = %+v, want only lab-router.pub", keys)
	}
	joined := strings.Join(problems, "\n")
	if !strings.Contains(joined, "loose.pub is writable") || !strings.Contains(joined, "broken.pub") {
		t.Errorf("problems = %q", joined)
	}

	// A directory others can write is not a trust anchor at all.
	if err := os.Chmod(trusted, 0o777); err != nil { //nolint:gosec // the point of the test
		t.Fatal(err)
	}
	keys, problems = store.Trusted()
	if len(keys) != 0 || !strings.Contains(strings.Join(problems, "\n"), "none of its keys are trusted") {
		t.Errorf("writable dir: keys %+v, problems %v", keys, problems)
	}
}

func TestDemoKeyStoreLivesInMemory(t *testing.T) {
	store := NewFake().SigningKeys()
	ctx := context.Background()
	if _, err := store.LocalSigner(ctx); !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("err = %v", err)
	}
	plan, err := store.PlanCreate()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range plan.Steps {
		if !strings.HasSuffix(step.Preview, "(demo: not run)") ||
			!strings.Contains(step.Preview, SigningKeyDir) {
			t.Errorf("demo step %q", step.Preview)
		}
	}
	if _, err := store.Create(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if keys, _ := store.Trusted(); len(keys) != 1 {
		t.Errorf("the demo machine does not trust its own key")
	}
}
