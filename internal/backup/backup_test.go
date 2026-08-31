package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"strings"
	"testing"
)

// sampleSources is a small but representative router identity used across the
// assemble/verify/preview tests. Every address is in a documentation range.
func sampleSources() Sources {
	return Sources{
		Nftables: "table inet filter {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n",
		Networkd: map[string]string{
			"10-wan0.network": "[Match]\nName=wan0\n[Network]\nDHCP=yes\n",
			"20-lan0.network": "[Match]\nName=lan0\n[Network]\nAddress=192.0.2.1/24\n",
		},
		DHCPDNS: "interface=lan0\ndhcp-range=192.0.2.100,192.0.2.200,12h\n",
		Wireguard: map[string]WGConf{
			"wg0": {Config: "[Interface]\nAddress = 10.0.0.1/24\n", KeyRef: "/etc/wireguard/wg0.key"},
		},
		Accounts: []Account{{Name: "netadmin", Role: "admin"}},
	}
}

func sampleMeta() Meta {
	return Meta{ToolVersion: "test", Hostname: "lab-router", Timestamp: "20260101-000000"}
}

func TestAssembleOpenRoundTrip(t *testing.T) {
	data, err := Assemble(sampleSources(), sampleMeta(), nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	art, err := Open(data, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if art.Manifest.Schema != SchemaVersion {
		t.Fatalf("schema = %d, want %d", art.Manifest.Schema, SchemaVersion)
	}
	if art.Manifest.Hostname != "lab-router" || art.Manifest.Timestamp != "20260101-000000" {
		t.Fatalf("manifest identity not preserved: %+v", art.Manifest)
	}
	if art.Signed {
		t.Fatal("unsigned artifact reports Signed")
	}
	if Diff(art.Sources, sampleSources()).HasChanges() {
		t.Fatalf("round-trip changed the logical state:\n%s",
			Diff(art.Sources, sampleSources()).String())
	}
	if got := art.Manifest.WireguardKeyRefs["wg0"]; got != "/etc/wireguard/wg0.key" {
		t.Fatalf("wireguard key slot not preserved: %q", got)
	}
}

func TestAssembleDeterministic(t *testing.T) {
	a, _ := Assemble(sampleSources(), sampleMeta(), nil)
	b, _ := Assemble(sampleSources(), sampleMeta(), nil)
	if !bytes.Equal(a, b) {
		t.Fatal("Assemble is not deterministic for equal inputs")
	}
}

func TestOpenRejectsWrongSchema(t *testing.T) {
	// Rebuild an artifact whose manifest claims a schema this build rejects.
	data, _ := Assemble(sampleSources(), sampleMeta(), nil)
	files := mustReadOrdered(t, data)
	for i := range files {
		if files[i].path == manifestPath {
			files[i].data = bytes.Replace(files[i].data,
				[]byte(`"schema": 1`), []byte(`"schema": 99`), 1)
		}
	}
	// Recompute the checksum file so the schema change is not caught as a
	// checksum mismatch first: this isolates the schema check.
	rebuilt := rebuildWithChecksums(t, files)
	if _, err := Open(rebuilt, nil); err == nil ||
		!strings.Contains(err.Error(), "schema") {
		t.Fatalf("want a schema error, got %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	data, _ := Assemble(sampleSources(), sampleMeta(), nil)
	files := mustReadOrdered(t, data)
	// Flip a byte inside the nftables part but leave MANIFEST.sha256 untouched,
	// so the checksum that covers it no longer matches.
	changed := false
	for i := range files {
		if files[i].path == nftablesPart && len(files[i].data) > 0 {
			files[i].data[0] ^= 0x20
			changed = true
		}
	}
	if !changed {
		t.Fatal("did not find the nftables part to tamper with")
	}
	tampered := rebuildKeepingChecksums(t, files)
	_, err := Open(tampered, nil)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want a checksum refusal, got %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewEd25519Signer(priv, "lab")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Assemble(sampleSources(), sampleMeta(), signer)
	if err != nil {
		t.Fatalf("assemble signed: %v", err)
	}

	verifier, err := NewEd25519Verifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	art, err := Open(data, verifier)
	if err != nil {
		t.Fatalf("open with correct key: %v", err)
	}
	if !art.Signed || !art.SignatureVerified {
		t.Fatalf("signed artifact not verified: %+v", art)
	}

	// A signed artifact opened without a verifier is fine, just not verified.
	art2, err := Open(data, nil)
	if err != nil {
		t.Fatalf("open signed without verifier: %v", err)
	}
	if !art2.Signed || art2.SignatureVerified {
		t.Fatalf("unverified path wrong: %+v", art2)
	}

	// A wrong key is a refusal.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	wrong, _ := NewEd25519Verifier(otherPub)
	if _, err := Open(data, wrong); err == nil {
		t.Fatal("verify accepted a wrong public key")
	}
}

func TestVerifierRequiresSignature(t *testing.T) {
	data, _ := Assemble(sampleSources(), sampleMeta(), nil)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	verifier, _ := NewEd25519Verifier(pub)
	if _, err := Open(data, verifier); err == nil ||
		!strings.Contains(err.Error(), "no SIGNATURE") {
		t.Fatalf("want a missing-signature refusal, got %v", err)
	}
}

func TestPreviewKinds(t *testing.T) {
	current := Sources{
		Nftables: "table inet filter {\n\tchain input {\n\t\ttcp dport 22 accept\n\t}\n}\n",
		Networkd: map[string]string{"10-wan0.network": "old\n"},
	}
	target := sampleSources()
	p := Diff(current, target)
	if !p.HasChanges() {
		t.Fatal("expected changes")
	}
	kinds := map[string]ChangeKind{}
	for _, c := range p.Changes {
		key := c.Subsystem
		if c.Item != "" {
			key += "/" + c.Item
		}
		kinds[key] = c.Kind
	}
	if kinds["nftables/ruleset"] != ChangeUnchanged {
		t.Fatalf("nftables should be unchanged, got %q", kinds["nftables/ruleset"])
	}
	if kinds["networkd/10-wan0.network"] != ChangeReplace {
		t.Fatalf("wan0 should be replace, got %q", kinds["networkd/10-wan0.network"])
	}
	if kinds["networkd/20-lan0.network"] != ChangeAdd {
		t.Fatalf("lan0 should be add, got %q", kinds["networkd/20-lan0.network"])
	}
	if kinds["wireguard/wg0"] != ChangeAdd {
		t.Fatalf("wg0 should be add, got %q", kinds["wireguard/wg0"])
	}
}

func TestOpenControlCharsSanitized(t *testing.T) {
	src := sampleSources()
	src.DHCPDNS = "interface=lan0\x00\x07\x1b[31m\ndhcp-range=x\n"
	data, _ := Assemble(src, sampleMeta(), nil)
	art, err := Open(data, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if strings.ContainsAny(art.Sources.DHCPDNS, "\x00\x07\x1b") {
		t.Fatalf("control characters survived: %q", art.Sources.DHCPDNS)
	}
}

func TestOpenRejectsNonGzip(t *testing.T) {
	if _, err := Open([]byte("not a gzip artifact"), nil); err == nil {
		t.Fatal("accepted non-gzip input")
	}
}

// --- test helpers -----------------------------------------------------------

// mustReadOrdered decompresses an artifact into its entries, in tar order.
func mustReadOrdered(t *testing.T, data []byte) []fileEntry {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []fileEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(tr)
		out = append(out, fileEntry{path: hdr.Name, data: content})
	}
	return out
}

// rebuildKeepingChecksums re-packs entries as they are, keeping whatever
// MANIFEST.sha256 already holds — used to simulate tampering.
func rebuildKeepingChecksums(t *testing.T, files []fileEntry) []byte {
	t.Helper()
	data, err := writeTarGz(files)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// rebuildWithChecksums re-packs entries and regenerates MANIFEST.sha256 to
// match, so a test can change the manifest without tripping the checksum gate.
func rebuildWithChecksums(t *testing.T, files []fileEntry) []byte {
	t.Helper()
	var manifestJSON []byte
	var parts []fileEntry
	for _, f := range files {
		switch f.path {
		case manifestPath:
			manifestJSON = f.data
		case checksumPath, signaturePath:
			// dropped; checksums are regenerated below
		default:
			parts = append(parts, f)
		}
	}
	rebuilt := []fileEntry{{path: manifestPath, data: manifestJSON}}
	rebuilt = append(rebuilt, parts...)
	rebuilt = append(rebuilt, fileEntry{
		path: checksumPath, data: buildChecksums(manifestJSON, parts),
	})
	data, err := writeTarGz(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
