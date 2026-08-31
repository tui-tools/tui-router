package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The reader treats an artifact as hostile input from another machine. These
// bounds cap what a single file may cost before it is understood, so a crafted
// artifact (a decompression bomb, a flood of entries) is refused rather than
// exhausting memory.
const (
	// maxArtifactBytes bounds the total uncompressed size read from the tar.
	maxArtifactBytes = 64 << 20 // 64 MiB
	// maxEntries bounds how many files the tar may contain.
	maxEntries = 512
	// maxEntryBytes bounds a single entry's size.
	maxEntryBytes = 16 << 20 // 16 MiB
)

// Artifact is a parsed, integrity-checked backup: its manifest, the logical
// Sources it carries, and whether it was signed. It is produced by Open, which
// refuses to return one whose checksums do not match.
type Artifact struct {
	Manifest Manifest
	Sources  Sources
	// Signed reports whether a SIGNATURE part was present. Whether it was
	// verified depends on whether a Verifier was supplied to Open.
	Signed bool
	// SignatureVerified reports whether the signature was checked and passed.
	SignatureVerified bool
}

// Open reads, sanitizes and verifies an artifact. Integrity is unconditional:
// every part and the manifest are checked against MANIFEST.sha256, and a single
// flipped byte makes Open refuse. A signature is checked only when verifier is
// non-nil, and then a missing or bad signature is also a refusal. On success
// the returned Artifact carries the scrubbed logical Sources.
func Open(data []byte, verifier Verifier) (*Artifact, error) {
	files, err := readTarGz(data)
	if err != nil {
		return nil, err
	}

	manifestJSON, ok := files[manifestPath]
	if !ok {
		return nil, errors.New("backup: the artifact has no manifest.json")
	}
	checksums, ok := files[checksumPath]
	if !ok {
		return nil, errors.New("backup: the artifact has no MANIFEST.sha256")
	}

	if err := verifyChecksums(checksums, files); err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return nil, fmt.Errorf("backup: the manifest is not valid JSON: %w", err)
	}
	if manifest.Schema != SchemaVersion {
		return nil, fmt.Errorf(
			"backup: artifact schema %d is not the %d this build understands",
			manifest.Schema, SchemaVersion)
	}
	if err := verifyManifestParts(manifest, files); err != nil {
		return nil, err
	}

	art := &Artifact{Manifest: manifest}

	if sigRaw, present := files[signaturePath]; present {
		art.Signed = true
		if verifier != nil {
			if err := verifySignature(sigRaw, checksums, verifier); err != nil {
				return nil, err
			}
			art.SignatureVerified = true
		}
	} else if verifier != nil {
		return nil, errors.New(
			"backup: a public key was given but the artifact carries no SIGNATURE")
	}

	art.Sources, err = sourcesFromParts(manifest, files)
	if err != nil {
		return nil, err
	}
	return art, nil
}

// readTarGz decompresses and unpacks the artifact into a path-to-bytes map,
// enforcing every safety bound and rejecting a name that is not a plain
// relative path. A duplicate name, a traversal, or an oversize stream is an
// error, never a silent last-wins.
func readTarGz(data []byte) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("backup: the artifact is not a gzip stream: %w", err)
	}
	defer func() { _ = gz.Close() }()

	limited := io.LimitReader(gz, maxArtifactBytes+1)
	tr := tar.NewReader(limited)
	files := map[string][]byte{}
	total := 0
	count := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: the artifact tar is malformed: %w", err)
		}
		count++
		if count > maxEntries {
			return nil, fmt.Errorf("backup: the artifact has more than %d entries", maxEntries)
		}
		if hdr.Typeflag != tar.TypeReg {
			// Directories and anything exotic (links, devices) carry no part
			// content and are simply skipped.
			continue
		}
		name, ok := safeName(hdr.Name)
		if !ok {
			return nil, fmt.Errorf("backup: unsafe entry name %q in the artifact", hdr.Name)
		}
		if _, dup := files[name]; dup {
			return nil, fmt.Errorf("backup: duplicate entry %q in the artifact", name)
		}
		if hdr.Size > maxEntryBytes {
			return nil, fmt.Errorf("backup: entry %q exceeds the per-file limit", name)
		}
		content, err := io.ReadAll(io.LimitReader(tr, maxEntryBytes+1))
		if err != nil {
			return nil, fmt.Errorf("backup: reading entry %q: %w", name, err)
		}
		if len(content) > maxEntryBytes {
			return nil, fmt.Errorf("backup: entry %q exceeds the per-file limit", name)
		}
		total += len(content)
		if total > maxArtifactBytes {
			return nil, errors.New("backup: the artifact exceeds the total size limit")
		}
		files[name] = content
	}
	return files, nil
}

// safeName reports whether a tar entry name is a plain relative path this
// reader will accept: no absolute path, no parent reference, no drive letter,
// no control character.
func safeName(name string) (string, bool) {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return "", false
	}
	if name != sanitizeText(name) || strings.ContainsAny(name, "\n\t") {
		return "", false
	}
	for _, seg := range strings.Split(name, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return "", false
		}
	}
	return name, true
}

// verifyChecksums recomputes the SHA-256 of every file the checksum manifest
// names and refuses on the first mismatch or missing file. Every file listed
// must be present with exactly the recorded hash; that is the unconditional
// integrity gate.
func verifyChecksums(checksums []byte, files map[string][]byte) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(checksums), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		want, path, ok := parseChecksumLine(line)
		if !ok {
			return fmt.Errorf("backup: malformed line in MANIFEST.sha256: %q", line)
		}
		content, present := files[path]
		if !present {
			return fmt.Errorf("backup: MANIFEST.sha256 names %q, which is missing", path)
		}
		if sum(content) != want {
			return fmt.Errorf("backup: %q fails its checksum — the artifact was altered", path)
		}
		seen[path] = true
	}
	if !seen[manifestPath] {
		return errors.New("backup: MANIFEST.sha256 does not cover the manifest")
	}
	return nil
}

// parseChecksumLine reads one "<hex>  <path>" line of the checksum file.
func parseChecksumLine(line string) (hash, path string, ok bool) {
	// sha256sum separates the hash and the name with two spaces.
	hash, path, found := strings.Cut(line, "  ")
	if !found {
		return "", "", false
	}
	hash = strings.TrimSpace(hash)
	path = strings.TrimSpace(path)
	if len(hash) != 64 || path == "" {
		return "", "", false
	}
	for _, c := range hash {
		if !isHex(c) {
			return "", "", false
		}
	}
	return hash, path, true
}

// isHex reports whether r is a lowercase hex digit.
func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')
}

// verifyManifestParts cross-checks the manifest's own per-part hashes against
// the files, so the two records of what the artifact contains cannot disagree.
func verifyManifestParts(m Manifest, files map[string][]byte) error {
	for _, p := range m.Parts {
		name, ok := safeName(p.Path)
		if !ok {
			return fmt.Errorf("backup: manifest names an unsafe part path %q", p.Path)
		}
		content, present := files[name]
		if !present {
			return fmt.Errorf("backup: manifest names part %q, which is missing", p.Path)
		}
		if sum(content) != p.SHA256 {
			return fmt.Errorf("backup: part %q fails the manifest checksum", p.Path)
		}
	}
	return nil
}

// verifySignature checks the detached signature over the checksum file.
func verifySignature(sigRaw, checksums []byte, verifier Verifier) error {
	sig, _, err := decodeSignature(sigRaw)
	if err != nil {
		return err
	}
	if err := verifier.Verify(checksums, sig); err != nil {
		return err
	}
	return nil
}

// sourcesFromParts rebuilds the logical Sources from the verified parts,
// sanitizing every text part on the way in. It walks the manifest, so only
// declared, checksum-matched parts are read.
func sourcesFromParts(m Manifest, files map[string][]byte) (Sources, error) {
	src := Sources{}
	// Sort parts for a deterministic walk regardless of manifest order.
	parts := append([]Part(nil), m.Parts...)
	sort.Slice(parts, func(i, j int) bool { return parts[i].Path < parts[j].Path })

	for _, p := range parts {
		content := files[p.Path] // presence already verified
		switch p.Subsystem {
		case SubsystemNftables:
			src.Nftables = sanitizeText(string(content))
		case SubsystemDHCPDNS:
			src.DHCPDNS = sanitizeText(string(content))
		case SubsystemNetworkd:
			name := unitName(p.Path, networkdDir)
			if name == "" {
				return Sources{}, fmt.Errorf("backup: bad networkd part path %q", p.Path)
			}
			if src.Networkd == nil {
				src.Networkd = map[string]string{}
			}
			src.Networkd[name] = sanitizeText(string(content))
		case SubsystemWireguard:
			name := strings.TrimSuffix(unitName(p.Path, wireguardDir), ".conf")
			if name == "" {
				return Sources{}, fmt.Errorf("backup: bad wireguard part path %q", p.Path)
			}
			if src.Wireguard == nil {
				src.Wireguard = map[string]WGConf{}
			}
			src.Wireguard[name] = WGConf{
				Config: sanitizeText(string(content)),
				KeyRef: m.WireguardKeyRefs[name],
			}
		case SubsystemAccounts:
			accounts, err := parseAccounts(content)
			if err != nil {
				return Sources{}, err
			}
			src.Accounts = accounts
		default:
			// An unknown subsystem is surfaced, not silently applied: refuse
			// so a restore never runs bytes it does not understand.
			return Sources{}, fmt.Errorf(
				"backup: part %q has unknown subsystem %q", p.Path, p.Subsystem)
		}
	}
	return src, nil
}

// unitName extracts and sanitizes the base name of a part under a fixed
// directory prefix.
func unitName(path, dir string) string {
	if !strings.HasPrefix(path, dir) {
		return ""
	}
	return sanitizeName(strings.TrimPrefix(path, dir))
}

// parseAccounts reads the accounts part, sanitizing every field.
func parseAccounts(content []byte) ([]Account, error) {
	var raw []Account
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, fmt.Errorf("backup: the accounts part is not valid JSON: %w", err)
	}
	out := make([]Account, 0, len(raw))
	for _, a := range raw {
		name := strings.TrimSpace(sanitizeText(a.Name))
		if name == "" {
			continue
		}
		out = append(out, Account{Name: name, Role: strings.TrimSpace(sanitizeText(a.Role))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
