package backup

import "strings"

// keyLineTokens are the WireGuard config keys whose value is secret key
// material. They are matched case-insensitively against the token before the
// "=" on each line. Note the tokens are single words (no space), so they never
// match the two-word privacy-scan pattern; they are the wg.conf grammar.
var keyLineTokens = map[string]bool{
	"privatekey":   true,
	"presharedkey": true,
}

// StripWireguard turns a raw wg-quick config, which carries key material, into
// the form the artifact stores: every secret-bearing line has its value
// removed and replaced with a slot marker, and the on-disk key reference (if
// the raw config named one via a "# KeyRef:" hint) is returned separately. The
// returned bool reports whether any key line was present, which the collector
// uses to know a real interface was read rather than an empty file.
//
// The rule is absolute: no secret byte survives into the returned config. A
// value is dropped before it is ever written to a Sources, so it cannot reach
// the tar.
func StripWireguard(raw string) (clean string, keyRef string, hadKey bool) {
	var b strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		// A "# KeyRef: /path" hint records where the material lives; keep the
		// path as a reference, never the material.
		if ref, ok := parseKeyRefHint(trimmed); ok {
			keyRef = ref
			b.WriteString(line)
			b.WriteByte('\n')
			continue
		}
		token, _, isAssign := strings.Cut(trimmed, "=")
		if isAssign && keyLineTokens[strings.ToLower(strings.TrimSpace(token))] {
			hadKey = true
			// Preserve the key name and indentation, drop the value.
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			b.WriteString(indent + strings.TrimSpace(token) +
				" = # removed; restored out of band\n")
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n") + "\n", keyRef, hadKey
}

// parseKeyRefHint reads a "# KeyRef: <path>" comment line, the slot the export
// uses to note which key file an interface's material lives in.
func parseKeyRefHint(trimmed string) (string, bool) {
	const marker = "# KeyRef:"
	if !strings.HasPrefix(trimmed, marker) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(trimmed, marker)), true
}
