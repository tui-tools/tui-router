package router

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The fixtures in testdata seed the parser tests and the fuzz corpus, and a
// fuzz crash writes a new one from real input. They are committed to a public
// repository, so a fixture that carried a routable address, a real MAC or a
// hostname captured from a machine would publish it. This test is the gate:
// every fixture must use documentation ranges only.
//
// The rule is the family's fixture-scrubbing convention — addresses in the
// RFC 5737 / RFC 3849 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24, 2001:db8::/32) and the 10.0.0.0/8 lab range, MACs in the
// RFC 7042 documentation range (00:00:5e:00:53:xx), and no home paths.

// ipv4Re finds any dotted-quad in a fixture.
var ipv4Re = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

// macRe finds any six-octet MAC.
var macRe = regexp.MustCompile(`\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)

// allowedIPv4 reports whether an address is in a documentation or private-lab
// range a fixture is allowed to carry.
func allowedIPv4(a, b, c int) bool {
	switch {
	case a == 192 && b == 0 && c == 2: // 192.0.2.0/24 (RFC 5737)
		return true
	case a == 198 && b == 51 && c == 100: // 198.51.100.0/24 (RFC 5737)
		return true
	case a == 203 && b == 0 && c == 113: // 203.0.113.0/24 (RFC 5737)
		return true
	case a == 10: // 10.0.0.0/8, the lab's own WireGuard/LAN range
		return true
	case a == 127: // loopback
		return true
	case a == 0: // 0.0.0.0, a wildcard, not an address
		return true
	case a == 255: // broadcast
		return true
	default:
		return false
	}
}

// allowedMAC reports whether a MAC is in the documentation range or is the
// all-zero / broadcast address a fixture legitimately carries.
func allowedMAC(mac string) bool {
	lower := strings.ToLower(mac)
	switch {
	case strings.HasPrefix(lower, "00:00:5e:00:53:"): // RFC 7042 documentation
		return true
	case lower == "00:00:00:00:00:00": // the unset address on lo
		return true
	case lower == "ff:ff:ff:ff:ff:ff": // broadcast
		return true
	default:
		return false
	}
}

func TestFixturesAreScrubbed(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // test reads its own committed testdata
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		text := string(data)

		for _, m := range ipv4Re.FindAllStringSubmatch(text, -1) {
			a, b, c := atoi(m[1]), atoi(m[2]), atoi(m[3])
			// A version string like iproute2-6.12.0 is not an address; the
			// leading octet of a real address is never above 255, and the
			// documentation ranges are the whitelist, so anything outside
			// them is flagged.
			if !allowedIPv4(a, b, c) {
				t.Errorf("%s carries a non-documentation IPv4 address %q", name, m[0])
			}
		}
		for _, mac := range macRe.FindAllString(text, -1) {
			if !allowedMAC(mac) {
				t.Errorf("%s carries a non-documentation MAC %q", name, mac)
			}
		}
		if strings.Contains(text, "/home/") || strings.Contains(text, "/root/") {
			t.Errorf("%s carries a home path", name)
		}
	}
}

// atoi parses a small decimal, returning -1 on failure so an odd match is
// treated as out of range rather than allowed.
func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}
