package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestParseNetworkdUnitReadsTheServer is the bug this file exists for: the LAN
// unit omarchy-router-nics writes carries a [DHCPServer] section, and the card
// used to see nothing at all in it.
func TestParseNetworkdUnitReadsTheServer(t *testing.T) {
	unit := ParseNetworkdUnit([]NetworkdFile{
		{Path: "/etc/systemd/network/20-lan0.network",
			Raw: fixture(t, "networkd-lan.network")},
	})
	if unit.Link != "lan0" {
		t.Errorf("link = %q, want lan0", unit.Link)
	}
	if unit.Address != "192.0.2.1/24" {
		t.Errorf("address = %q, want 192.0.2.1/24", unit.Address)
	}
	if !unit.Enabled || !unit.HasSection {
		t.Errorf("enabled = %v, hasSection = %v, want both true", unit.Enabled, unit.HasSection)
	}
	if unit.PoolOffset != 100 || unit.PoolSize != 101 {
		t.Errorf("pool keys = %d/%d, want 100/101", unit.PoolOffset, unit.PoolSize)
	}
	if !unit.HasSubnet() {
		t.Error("a unit on 192.0.2.1/24 has a subnet to hand out")
	}
	start, end, ok := unit.Pool()
	if !ok || start != "192.0.2.100" || end != "192.0.2.200" {
		t.Errorf("pool = %s-%s (ok=%v), want 192.0.2.100-192.0.2.200", start, end, ok)
	}
}

// TestParseNetworkdUnitFoldsDropins covers the merge: a drop-in assigning a
// scalar again replaces the unit's value, which is how tui-network's
// 50-tui-network-dhcp.conf moves a pool without editing the profile's file.
func TestParseNetworkdUnitFoldsDropins(t *testing.T) {
	unit := ParseNetworkdUnit([]NetworkdFile{
		{Path: "/etc/systemd/network/20-lan0.network",
			Raw: fixture(t, "networkd-lan.network")},
		{Path: "/etc/systemd/network/20-lan0.network.d/50-tui-network-dhcp.conf",
			Raw: fixture(t, "networkd-lan-dropin.conf")},
	})
	if unit.PoolOffset != 50 || unit.PoolSize != 20 {
		t.Fatalf("pool keys = %d/%d, want the drop-in's 50/20",
			unit.PoolOffset, unit.PoolSize)
	}
	// The drop-in says nothing about [Match] or [Network], so the unit's link
	// and address survive it.
	if unit.Link != "lan0" || unit.Address != "192.0.2.1/24" {
		t.Errorf("drop-in lost the unit's link/address: %q %q", unit.Link, unit.Address)
	}
	if len(unit.Dropins) != 1 {
		t.Errorf("dropins = %v, want the one file", unit.Dropins)
	}
	start, end, ok := unit.Pool()
	if !ok || start != "192.0.2.50" || end != "192.0.2.69" {
		t.Errorf("pool = %s-%s (ok=%v), want 192.0.2.50-192.0.2.69", start, end, ok)
	}
}

// TestNetworkdContainerTemplateHasNoSubnet keeps systemd's own container and
// VM templates off the card: they run a real DHCP server, but on a null
// address the daemon fills in per interface, so there is no pool to name.
func TestNetworkdContainerTemplateHasNoSubnet(t *testing.T) {
	unit := ParseNetworkdUnit([]NetworkdFile{
		{Path: "/usr/lib/systemd/network/80-container-ve.network",
			Raw: fixture(t, "networkd-container.network")},
	})
	if !unit.Enabled {
		t.Error("the template does declare DHCPServer=yes")
	}
	if unit.HasSubnet() {
		t.Error("0.0.0.0/28 is not a subnet the card can describe")
	}
	if _, _, ok := unit.Pool(); ok {
		t.Error("a null address has no pool")
	}
}

// TestNetworkdPoolRange is systemd's own arithmetic
// (sd_dhcp_server_configure_pool): offset zero means one, size zero means the
// rest of the subnet below the broadcast address.
func TestNetworkdPoolRange(t *testing.T) {
	cases := []struct {
		name           string
		address        string
		offset, size   int
		wantStart, end string
		wantErr        bool
	}{
		{name: "defaults take the whole subnet", address: "192.0.2.1/24",
			wantStart: "192.0.2.1", end: "192.0.2.254"},
		{name: "explicit offset and size", address: "192.0.2.1/24",
			offset: 100, size: 101, wantStart: "192.0.2.100", end: "192.0.2.200"},
		{name: "offset only runs to the broadcast", address: "192.0.2.1/24",
			offset: 200, wantStart: "192.0.2.200", end: "192.0.2.254"},
		{name: "a /30 has two addresses", address: "10.0.0.1/30",
			wantStart: "10.0.0.1", end: "10.0.0.2"},
		{name: "the server's own address may sit in the pool",
			address: "192.0.2.10/24", offset: 1, size: 20,
			wantStart: "192.0.2.1", end: "192.0.2.20"},
		{name: "a size past the broadcast is refused", address: "192.0.2.1/24",
			offset: 250, size: 100, wantErr: true},
		{name: "an offset past the broadcast is refused", address: "192.0.2.1/24",
			offset: 255, wantErr: true},
		{name: "a null address has no fixed pool", address: "0.0.0.0/28", wantErr: true},
		{name: "a /31 leaves nothing to hand out", address: "192.0.2.0/31", wantErr: true},
		{name: "a bare address is not a subnet", address: "192.0.2.1", wantErr: true},
		{name: "an empty address is not a subnet", address: "", wantErr: true},
		{name: "IPv6 is not this server's pool", address: "2001:db8::1/64", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := NetworkdPoolRange(tc.address, tc.offset, tc.size)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %s-%s", start, end)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if start != tc.wantStart || end != tc.end {
				t.Errorf("pool = %s-%s, want %s-%s", start, end, tc.wantStart, tc.end)
			}
		})
	}
}

func TestCountNetworkctlLeases(t *testing.T) {
	if n := CountNetworkctlLeases(fixture(t, "networkctl-status.txt")); n != 3 {
		t.Errorf("leases = %d, want 3", n)
	}
	if n := CountNetworkctlLeases(fixture(t, "networkctl-status-noleases.txt")); n != 0 {
		t.Errorf("a link with no server offers no leases, got %d", n)
	}
	if n := CountNetworkctlLeases("Offered DHCP leases: none\n"); n != 0 {
		t.Errorf("`none` is not a lease, got %d", n)
	}
	if n := CountNetworkctlLeases(""); n != 0 {
		t.Errorf("no output is no leases, got %d", n)
	}
}

// TestNetworkdDHCPUnitsDiscovery walks a fixture tree the way the real
// backend walks systemd's search directories: /etc wins a unit name, the
// drop-ins of that name apply over it, and a unit with no subnet of its own is
// left out.
func TestNetworkdDHCPUnitsDiscovery(t *testing.T) {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	usrlib := filepath.Join(root, "usr-lib")
	write := func(dir, name, content string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(etc, "20-lan0.network", fixture(t, "networkd-lan.network"))
	write(filepath.Join(etc, "20-lan0.network.d"), "50-tui-network-dhcp.conf",
		fixture(t, "networkd-lan-dropin.conf"))
	write(usrlib, "80-container-ve.network", fixture(t, "networkd-container.network"))
	// A unit of the same name in a later directory must not be seen: /etc
	// claims the name.
	write(usrlib, "20-lan0.network", "[Match]\nName=nope\n")
	write(etc, "10-wan0.network", "[Match]\nName=wan0\n\n[Network]\nDHCP=yes\n")

	r := &Real{networkdDirs: []string{etc, usrlib}}
	units := r.networkdDHCPUnits()
	if len(units) != 1 {
		t.Fatalf("found %d units, want only the LAN one: %+v", len(units), units)
	}
	unit := units[0]
	if unit.Link != "lan0" {
		t.Errorf("link = %q, want lan0", unit.Link)
	}
	if unit.PoolOffset != 50 || unit.PoolSize != 20 {
		t.Errorf("the /etc drop-in did not win: %d/%d", unit.PoolOffset, unit.PoolSize)
	}
	if len(unit.Dropins) != 1 {
		t.Errorf("dropins = %v, want the one under /etc", unit.Dropins)
	}
}

// TestReadDHCPFindsTheNetworkdServer is the whole read path on a machine with
// no DHCP package: the card must name systemd-networkd rather than report
// nothing. systemctl is not reachable in a test, so the server reads as
// configured-but-not-running — the point here is that it is found at all.
func TestReadDHCPFindsTheNetworkdServer(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "20-lan0.network"),
		[]byte(fixture(t, "networkd-lan.network")), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &Real{networkdDirs: []string{root}}
	d := r.readDHCP(context.Background())
	if d.Server != ServerNetworkd {
		t.Fatalf("server = %q, want %s", d.Server, ServerNetworkd)
	}
	if d.Link != "lan0" {
		t.Errorf("link = %q, want lan0", d.Link)
	}
	if d.PoolStart != "192.0.2.100" || d.PoolEnd != "192.0.2.200" {
		t.Errorf("pool = %s-%s, want 192.0.2.100-192.0.2.200", d.PoolStart, d.PoolEnd)
	}
	if len(d.Units) != 1 {
		t.Errorf("units = %v, want the one unit read", d.Units)
	}
}

// TestDHCPCardNetworkdSummary pins the line the cockpit and --check both show.
func TestDHCPCardNetworkdSummary(t *testing.T) {
	cases := []struct {
		name string
		dhcp DHCP
		want string
	}{
		{
			name: "serving",
			dhcp: DHCP{Server: ServerNetworkd, Active: true, Leases: 7, Link: "lan0",
				PoolStart: "192.0.2.100", PoolEnd: "192.0.2.200"},
			want: "systemd-networkd · lan0 · pool 192.0.2.100-192.0.2.200 · 7 leases",
		},
		{
			name: "configured but switched off",
			dhcp: DHCP{Server: ServerNetworkd, Leases: -1, Link: "lan0",
				PoolStart: "192.0.2.100", PoolEnd: "192.0.2.200"},
			want: "systemd-networkd · lan0 · pool 192.0.2.100-192.0.2.200 · stopped",
		},
		{
			name: "leases unreadable",
			dhcp: DHCP{Server: ServerNetworkd, Active: true, Leases: -1, Link: "lan0"},
			want: "systemd-networkd · lan0",
		},
		{
			name: "dnsmasq keeps its own line",
			dhcp: DHCP{Server: ServerDnsmasq, Active: true, Leases: 4},
			want: "dnsmasq · active · 4 leases",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			card := dhcpCard(Snapshot{DHCP: tc.dhcp})
			if card.Summary != tc.want {
				t.Errorf("summary = %q, want %q", card.Summary, tc.want)
			}
		})
	}
}
