package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The family rule: every package turning bytes it did not write into values
// the tool acts on carries a Go native fuzz test, seeded from its testdata —
// see tui-kit/templates/FUZZING.md. The cockpit has five such parsers (ip -j
// interfaces and routes, /proc/net/dev, the wg dump, the lease count, and the
// three firewall postures), and one target below covers each. Every target
// asserts an invariant a caller may assume for any input at all, not an output
// for a known one: not panicking is the floor, not the goal.

// seed loads named testdata files as fuzz seeds, plus the shapes a real
// capture never has: nothing, a blank line, a truncated line.
func seed(f *testing.F, names ...string) {
	f.Helper()
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // test reads its own committed testdata
		if err != nil {
			f.Fatalf("read seed %s: %v", name, err)
		}
		f.Add(string(data))
	}
	f.Add("")
	f.Add("\n")
	f.Add("   ")
}

// substring fails when a parser emits something that was not in its input: a
// parser may report what it read, never invent or leak.
func substring(t *testing.T, input, value, what string) {
	t.Helper()
	if value != "" && !strings.Contains(input, value) {
		t.Fatalf("%s %q is not a substring of the input", what, value)
	}
}

func FuzzParseInterfaces(f *testing.F) {
	addr, err := os.ReadFile(filepath.Join("testdata", "ip-addr.json")) //nolint:gosec // test reads its own committed testdata
	if err != nil {
		f.Fatal(err)
	}
	route, err := os.ReadFile(filepath.Join("testdata", "ip-route.json")) //nolint:gosec // test reads its own committed testdata
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(addr), string(route))
	f.Add("", "")
	f.Add("[]", "[]")
	f.Add("not json", "not json")
	f.Add(string(addr), "garbage")

	f.Fuzz(func(t *testing.T, addrJSON, routeJSON string) {
		for _, iface := range ParseInterfaces(addrJSON, routeJSON) {
			if iface.Name == "" {
				t.Fatalf("interface with no name: %+v", iface)
			}
			substring(t, addrJSON, iface.Name, "interface name")
			substring(t, addrJSON, iface.IPv4, "interface address")
			switch iface.Role {
			case "wan", "lan", "other":
			default:
				t.Fatalf("interface %q has an invalid role %q", iface.Name, iface.Role)
			}
		}
	})
}

func FuzzParseProcNetDev(f *testing.F) {
	seed(f, "proc-net-dev.txt")
	f.Fuzz(func(t *testing.T, text string) {
		for _, c := range ParseProcNetDev(text) {
			if c.Name == "" {
				t.Fatalf("counter with no interface name: %+v", c)
			}
			if strings.ContainsAny(c.Name, " :|\t") {
				t.Fatalf("interface name kept /proc/net/dev syntax: %q", c.Name)
			}
			substring(t, text, c.Name, "interface name")
		}
	})
}

func FuzzParseWgDump(f *testing.F) {
	seed(f, "wg-dump.txt")
	f.Fuzz(func(t *testing.T, text string) {
		for _, iface := range ParseWgDump(text) {
			if iface.Name == "" {
				t.Fatalf("wg interface with no name: %+v", iface)
			}
			if iface.Peers < 0 || iface.Handshakes < 0 {
				t.Fatalf("negative counts: %+v", iface)
			}
			if iface.Handshakes > iface.Peers {
				t.Fatalf("more handshakes than peers: %+v", iface)
			}
			substring(t, text, iface.Name, "wg interface name")
		}
	})
}

func FuzzCountDnsmasqLeases(f *testing.F) {
	seed(f, "dnsmasq.leases")
	f.Fuzz(func(t *testing.T, text string) {
		n := CountDnsmasqLeases(text)
		if n < 0 {
			t.Fatalf("negative lease count %d", n)
		}
		if got := strings.Count(text, "\n") + 1; n > got {
			t.Fatalf("counted %d leases from at most %d lines", n, got)
		}
	})
}

func FuzzParseFirewalldListAll(f *testing.F) {
	seed(f, "firewalld-listall.txt")
	f.Fuzz(func(t *testing.T, text string) {
		p := ParseFirewalldListAll(text)
		if p.Backend != "firewalld" {
			t.Fatalf("backend = %q", p.Backend)
		}
		if p.Rules < 0 {
			t.Fatalf("negative rule count %d", p.Rules)
		}
		if p.Summary == "" {
			t.Fatal("posture has no summary")
		}
	})
}

func FuzzParseNftRuleset(f *testing.F) {
	seed(f, "nft-ruleset.txt")
	f.Fuzz(func(t *testing.T, text string) {
		p := ParseNftRuleset(text)
		if p.Backend != "nftables" {
			t.Fatalf("backend = %q", p.Backend)
		}
		if p.Rules < 0 {
			t.Fatalf("negative rule count %d", p.Rules)
		}
		if p.Summary == "" {
			t.Fatal("posture has no summary")
		}
	})
}

func FuzzParseUfwStatus(f *testing.F) {
	seed(f, "ufw-status.txt")
	f.Fuzz(func(t *testing.T, text string) {
		p := ParseUfwStatus(text)
		if p.Backend != "ufw" {
			t.Fatalf("backend = %q", p.Backend)
		}
		if p.Rules < 0 {
			t.Fatalf("negative rule count %d", p.Rules)
		}
		if p.Summary == "" {
			t.Fatal("posture has no summary")
		}
	})
}
