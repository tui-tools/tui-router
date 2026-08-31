package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tui-tools/tui-router/internal/backup"
	"github.com/tui-tools/tui-router/internal/router"
)

// TestDemoRoundTrip is the export→restore loop the spec asks for: exporting the
// demo router and restoring the artifact into a clean demo reproduces the same
// logical state, with no root and no real router.
func TestDemoRoundTrip(t *testing.T) {
	ctx := context.Background()
	src := router.NewFake()
	srcSources, err := src.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}

	data, err := backup.Assemble(srcSources,
		backup.Meta{ToolVersion: "test", Hostname: "demo-router", Timestamp: "20260101-000000"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	art, err := backup.Open(data, nil)
	if err != nil {
		t.Fatal(err)
	}

	dst := router.NewEmptyFake()
	keepConfirmed := func() bool { return true }
	if err := applyRestore(ctx, dst, art.Sources, time.Second, keepConfirmed, io.Discard); err != nil {
		t.Fatalf("applyRestore: %v", err)
	}

	dstSources, err := dst.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if backup.Diff(dstSources, srcSources).HasChanges() {
		t.Fatalf("restore did not reproduce the state:\n%s",
			backup.Diff(dstSources, srcSources).String())
	}
}

// TestNoSecretsInArtifact asserts the demo's WireGuard key material never lands
// in the exported artifact — not in a part, not anywhere in the bytes.
func TestNoSecretsInArtifact(t *testing.T) {
	ctx := context.Background()
	src := router.NewFake()
	srcSources, err := src.CollectSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := backup.Assemble(srcSources,
		backup.Meta{ToolVersion: "test", Hostname: "demo-router", Timestamp: "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(data, []byte(router.DemoWireguardSecret)) {
		t.Fatal("the key material appears in the raw artifact bytes")
	}
	for name, content := range decompressParts(t, data) {
		if strings.Contains(string(content), router.DemoWireguardSecret) {
			t.Fatalf("the key material appears in part %q", name)
		}
	}
}

// TestExportRestoreSignedCLI drives the actual export and restore commands with
// a signing key and a verify key, end to end.
func TestExportRestoreSignedCLI(t *testing.T) {
	dir := t.TempDir()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "sign.key")
	pubPath := filepath.Join(dir, "sign.pub")
	writeFile(t, keyPath, base64.StdEncoding.EncodeToString(priv.Seed()))
	writeFile(t, pubPath, base64.StdEncoding.EncodeToString(pub))

	artifact := filepath.Join(dir, "demo.tuiback")
	var out bytes.Buffer
	if err := runExport([]string{"--demo", "--sign", keyPath, "--out", artifact}, "stamp", &out); err != nil {
		t.Fatalf("export: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "signed: yes") {
		t.Fatalf("export did not report a signature: %s", out.String())
	}

	out.Reset()
	if err := runRestore([]string{"--demo", "--verify", pubPath, "--dry-run", artifact},
		strings.NewReader(""), &out); err != nil {
		t.Fatalf("restore --dry-run: %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "verified") {
		t.Fatalf("restore did not verify the signature: %s", out.String())
	}
	if !strings.Contains(out.String(), "nothing was applied") {
		t.Fatalf("dry-run applied something: %s", out.String())
	}
}

// TestRestoreRefusesTamperedCLI flips a byte in an exported artifact and asserts
// the restore command refuses it.
func TestRestoreRefusesTamperedCLI(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "demo.tuiback")
	var out bytes.Buffer
	if err := runExport([]string{"--demo", "--out", artifact}, "stamp", &out); err != nil {
		t.Fatalf("export: %v", err)
	}

	data, err := os.ReadFile(artifact) //nolint:gosec // the path is a test tempdir file
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte late in the stream, inside the compressed payload.
	data[len(data)/2] ^= 0x40
	writeRawFile(t, artifact, data)

	out.Reset()
	err = runRestore([]string{"--demo", artifact}, strings.NewReader(""), &out)
	if err == nil {
		t.Fatalf("restore accepted a tampered artifact:\n%s", out.String())
	}
}

// TestNftablesRollbackOnNoKeep asserts the connectivity-safe path: when the
// operator does not confirm the new ruleset, it is rolled back to the snapshot
// and the restore reports the rollback.
func TestNftablesRollbackOnNoKeep(t *testing.T) {
	ctx := context.Background()
	dst := router.NewEmptyFake() // starts with an empty ruleset
	target := backup.Sources{Nftables: "table inet filter {\n\tchain input {\n\t}\n}\n"}

	notConfirmed := func() bool { return false }
	err := applyRestore(ctx, dst, target, time.Second, notConfirmed, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want a rollback error, got %v", err)
	}
	after, _ := dst.NftablesSnapshot(ctx)
	if strings.TrimSpace(after) != "" {
		t.Fatalf("ruleset was not rolled back to the empty snapshot: %q", after)
	}
}

// --- helpers ----------------------------------------------------------------

func decompressParts(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(tr)
		out[hdr.Name] = content
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeRawFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil { //nolint:gosec // the path is a test tempdir file
		t.Fatal(err)
	}
}
