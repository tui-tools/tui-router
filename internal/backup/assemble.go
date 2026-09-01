package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// fileEntry is one file on its way into the tar: where it goes, its bytes, and
// the subsystem it serves ("" for the fixed non-part files).
type fileEntry struct {
	path      string
	data      []byte
	subsystem string
}

// Assemble serializes Sources into the artifact bytes: a gzip'd tar carrying
// the manifest, one part per subsystem, the always-present MANIFEST.sha256, and
// — only when signer is non-nil — a detached SIGNATURE over that checksum file.
//
// It is pure and deterministic: the same Sources and Meta produce byte-identical
// output (the tar entries carry a zero mod-time and are emitted in a fixed
// order), which is what lets a test reason about the result. No secret is ever
// placed in a part; that scrubbing happened when the Sources were collected.
func Assemble(src Sources, meta Meta, signer Signer) ([]byte, error) {
	parts := partFiles(src)

	manifest := Manifest{
		Schema:           SchemaVersion,
		ToolVersion:      meta.ToolVersion,
		Hostname:         meta.Hostname,
		Timestamp:        meta.Timestamp,
		WireguardKeyRefs: wireguardKeyRefs(src),
	}
	for _, p := range parts {
		manifest.Parts = append(manifest.Parts, Part{
			Path:      p.path,
			Subsystem: p.subsystem,
			Bytes:     len(p.data),
			SHA256:    sum(p.data),
		})
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("backup: encoding the manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')

	// The checksum file covers the manifest and every part, so tampering with
	// any of them is caught. The signature (when present) covers this file, so
	// tampering with the checksums themselves is caught too.
	checksums := buildChecksums(manifestJSON, parts)

	entries := []fileEntry{{path: manifestPath, data: manifestJSON}}
	entries = append(entries, parts...)
	entries = append(entries, fileEntry{path: checksumPath, data: checksums})

	if signer != nil {
		sig, err := signer.Sign(checksums)
		if err != nil {
			return nil, fmt.Errorf("backup: signing the checksum file: %w", err)
		}
		entries = append(entries, fileEntry{
			path: signaturePath, data: encodeSignature(sig, signer.KeyID()),
		})
	}

	return writeTarGz(entries)
}

// partFiles renders every subsystem as its part files, in a fixed order so the
// output is deterministic. A subsystem with nothing to say contributes no file.
func partFiles(src Sources) []fileEntry {
	var parts []fileEntry

	if strings.TrimSpace(src.Nftables) != "" {
		parts = append(parts, fileEntry{
			path: nftablesPart, subsystem: SubsystemNftables,
			data: []byte(ensureTrailingNewline(src.Nftables)),
		})
	}

	// The four supporting config files: the role assignment the profile reads,
	// the forwarding and resolver drop-ins, and tui-firewall's saved ruleset.
	// Each is a single text file, emitted only when the router has one.
	for _, single := range []struct {
		path, subsystem, content string
	}{
		{rolesPart, SubsystemRoles, src.Roles},
		{sysctlPart, SubsystemSysctl, src.Sysctl},
		{resolvedPart, SubsystemResolved, src.Resolved},
		{firewallRulesPart, SubsystemFirewallRules, src.FirewallRules},
	} {
		if strings.TrimSpace(single.content) == "" {
			continue
		}
		parts = append(parts, fileEntry{
			path: single.path, subsystem: single.subsystem,
			data: []byte(ensureTrailingNewline(single.content)),
		})
	}

	for _, name := range sortedKeys(src.Networkd) {
		parts = append(parts, fileEntry{
			path: networkdDir + name, subsystem: SubsystemNetworkd,
			data: []byte(src.Networkd[name]),
		})
	}

	if strings.TrimSpace(src.DHCPDNS) != "" {
		parts = append(parts, fileEntry{
			path: dhcpDNSPart, subsystem: SubsystemDHCPDNS,
			data: []byte(ensureTrailingNewline(src.DHCPDNS)),
		})
	}

	for _, name := range sortedWGKeys(src.Wireguard) {
		parts = append(parts, fileEntry{
			path: wireguardDir + name + ".conf", subsystem: SubsystemWireguard,
			data: []byte(ensureTrailingNewline(src.Wireguard[name].Config)),
		})
	}

	if len(src.Accounts) > 0 {
		// Marshal a copy so the export order is stable regardless of the caller.
		accounts := append([]Account(nil), src.Accounts...)
		sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
		data, _ := json.MarshalIndent(accounts, "", "  ")
		parts = append(parts, fileEntry{
			path: accountsPart, subsystem: SubsystemAccounts,
			data: append(data, '\n'),
		})
	}

	return parts
}

// wireguardKeyRefs collects the interface-to-key-path slots for the manifest.
func wireguardKeyRefs(src Sources) map[string]string {
	if len(src.Wireguard) == 0 {
		return nil
	}
	refs := map[string]string{}
	for name, conf := range src.Wireguard {
		if conf.KeyRef != "" {
			refs[name] = conf.KeyRef
		}
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

// buildChecksums renders the sha256sum-style checksum file over the manifest
// and every part, in the order they appear in the tar.
func buildChecksums(manifestJSON []byte, parts []fileEntry) []byte {
	var b strings.Builder
	b.WriteString(sum(manifestJSON) + "  " + manifestPath + "\n")
	for _, p := range parts {
		b.WriteString(sum(p.data) + "  " + p.path + "\n")
	}
	return []byte(b.String())
}

// writeTarGz packs the entries into a gzip'd tar with deterministic headers.
func writeTarGz(entries []fileEntry) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:   e.path,
			Mode:   0o600,
			Size:   int64(len(e.data)),
			Format: tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("backup: writing tar header for %s: %w", e.path, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			return nil, fmt.Errorf("backup: writing %s: %w", e.path, err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("backup: closing the tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("backup: closing the gzip stream: %w", err)
	}
	return buf.Bytes(), nil
}

// sum is the lowercase hex SHA-256 of b, the form the checksum file and the
// manifest both use.
func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ensureTrailingNewline guarantees a text part ends in exactly one newline, so
// two exports of the same logical config never differ over a final byte.
func ensureTrailingNewline(s string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return s + "\n"
}

// sortedKeys returns the keys of a string map in sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortedWGKeys returns the interface names of a WireGuard map in sorted order.
func sortedWGKeys(m map[string]WGConf) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
