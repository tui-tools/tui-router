package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixture reads a testdata file or fails the test.
func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // test reads its own committed testdata
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestParseInterfaces(t *testing.T) {
	ifaces := ParseInterfaces(fixture(t, "ip-addr.json"), fixture(t, "ip-route.json"))

	byName := map[string]Interface{}
	for _, iface := range ifaces {
		byName[iface.Name] = iface
	}

	// eth0 carries the default route: it is the WAN, and it is up with its
	// global address.
	if eth0 := byName["eth0"]; eth0.Role != "wan" || !eth0.Up || eth0.IPv4 != "198.51.100.20" {
		t.Errorf("eth0 = %+v, want wan/up/198.51.100.20", eth0)
	}
	// eth1 has a directly attached subnet: it is the LAN.
	if eth1 := byName["eth1"]; eth1.Role != "lan" || eth1.IPv4 != "192.0.2.1" {
		t.Errorf("eth1 = %+v, want lan/192.0.2.1", eth1)
	}
	// wg0 is up despite operstate UNKNOWN, and it is neither WAN nor LAN.
	if wg0 := byName["wg0"]; !wg0.Up || wg0.Role != "other" {
		t.Errorf("wg0 = %+v, want up/other", wg0)
	}
	// eth2 has no UP flag: it is down.
	if eth2 := byName["eth2"]; eth2.Up {
		t.Errorf("eth2 should be down: %+v", eth2)
	}
	// lo carries only host addresses, so it reports no global IPv4.
	if lo := byName["lo"]; lo.IPv4 != "" {
		t.Errorf("lo should have no global IPv4: %+v", lo)
	}
}

func TestParseProcNetDev(t *testing.T) {
	counters := ParseProcNetDev(fixture(t, "proc-net-dev.txt"))
	byName := map[string]Counter{}
	for _, c := range counters {
		byName[c.Name] = c
	}
	if eth0 := byName["eth0"]; eth0.RxBytes != 8402850298 || eth0.TxBytes != 3034968383 {
		t.Errorf("eth0 counters = %+v", eth0)
	}
	// The two header lines carry a `|`, not a real interface.
	for _, c := range counters {
		if c.Name == "Inter-" || c.Name == "face" {
			t.Errorf("a header line was read as an interface: %q", c.Name)
		}
	}
}

func TestParseWgDump(t *testing.T) {
	ifaces := ParseWgDump(fixture(t, "wg-dump.txt"))
	if len(ifaces) != 1 {
		t.Fatalf("got %d interfaces, want 1", len(ifaces))
	}
	wg0 := ifaces[0]
	if wg0.Name != "wg0" || wg0.Peers != 2 || wg0.Handshakes != 1 {
		t.Errorf("wg0 = %+v, want wg0/2 peers/1 handshake", wg0)
	}
}

func TestCountDnsmasqLeases(t *testing.T) {
	if n := CountDnsmasqLeases(fixture(t, "dnsmasq.leases")); n != 4 {
		t.Errorf("lease count = %d, want 4", n)
	}
	if n := CountDnsmasqLeases(""); n != 0 {
		t.Errorf("empty file counted %d leases", n)
	}
}

func TestParseFirewalldListAll(t *testing.T) {
	p := ParseFirewalldListAll(fixture(t, "firewalld-listall.txt"))
	if !p.Masquerade {
		t.Error("masquerade should be read as on")
	}
	// two services (dhcpv6-client, ssh) + one port (51820/udp) = 3 openings.
	if p.Rules != 3 {
		t.Errorf("rule count = %d, want 3", p.Rules)
	}
}

func TestParseNftRuleset(t *testing.T) {
	p := ParseNftRuleset(fixture(t, "nft-ruleset.txt"))
	if !p.Masquerade {
		t.Error("masquerade should be read as on")
	}
	if p.Rules == 0 {
		t.Error("expected some rules")
	}
	// the input chain policy is drop; the summary quotes it.
	if want := "input drop"; !strings.Contains(p.Summary, want) {
		t.Errorf("summary = %q, want it to contain %q", p.Summary, want)
	}
}

func TestParseUfwStatus(t *testing.T) {
	p := ParseUfwStatus(fixture(t, "ufw-status.txt"))
	if !p.Active {
		t.Error("ufw should be read as active")
	}
	if p.Rules != 3 {
		t.Errorf("rule count = %d, want 3", p.Rules)
	}
}
