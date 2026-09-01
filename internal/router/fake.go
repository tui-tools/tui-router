package router

import (
	"context"
	"fmt"
	"time"

	"github.com/tui-tools/tui-router/internal/backup"
)

// Fake is the in-memory backend behind --demo and the tests: a plausible
// office router with two interfaces, an active firewall, live traffic, a
// dnsmasq handing out leases and a WireGuard interface with peers. It builds
// every card so the whole cockpit renders on a machine that has none of these
// backends installed — and it reports every managing tool as absent, so ENTER
// says so rather than trying to launch anything.
type Fake struct {
	started time.Time
	// installed is the set of managing tools the demo pretends are present;
	// empty by default so the demo shows the "not installed" path.
	installed map[string]bool
	// roles is the demo's role-assignment state, driven by the roles wizard
	// (see roles_fake.go).
	roles *fakeRoles

	// The fields below are the demo's in-memory "disk": the state export reads
	// and restore writes, so the whole backup loop runs with no root and no
	// real router. rawWG deliberately holds key material, exactly as a real
	// /etc/wireguard/*.conf would, so the collector's stripping is exercised
	// and the no-secrets test has something real to assert never leaked.
	nft      string
	networkd map[string]string
	dhcpDNS  string
	rawWG    map[string]string
	accounts []Account
}

// Account mirrors backup.Account for the demo backend, so the demo's seed
// reads without reaching into the backup package at every use site.
type Account = backup.Account

// DemoWireguardSecret is the fake key material the demo's WireGuard config
// carries. It is documentation-only, and the no-secrets test asserts these
// bytes never reach an assembled artifact.
const DemoWireguardSecret = "DEMOprivateKEYshouldNEVERleak0000000000000ab="

// NewFake returns the sample router, seeded with a plausible logical state so
// `--demo export` and `--demo restore` both have something real to work on.
func NewFake() *Fake {
	return &Fake{
		started:   time.Now(),
		installed: map[string]bool{},
		roles:     &fakeRoles{content: demoRolesConf},
		nft:       demoNftRuleset,
		networkd: map[string]string{
			"10-wan0.network": demoWanNetwork,
			"20-lan0.network": demoLanNetwork,
		},
		dhcpDNS: demoDnsmasqConf,
		rawWG: map[string]string{
			"wg0": demoWireguardConf,
		},
		accounts: []Account{
			{Name: "netadmin", Role: "admin"},
			{Name: "monitor", Role: "readonly"},
		},
	}
}

// NewEmptyFake returns a demo backend with no logical state, the clean machine
// a restore writes into during the round-trip test. Its roles state exists but
// is empty, so a restore has to put the role assignment back too.
func NewEmptyFake() *Fake {
	return &Fake{started: time.Now(), installed: map[string]bool{},
		roles: &fakeRoles{content: ""}}
}

// demoInterfaces is the sample router's NIC list, shared by the snapshot and
// the roles wizard's MAC resolution. The MACs are from the RFC 7042
// documentation range, the same rule the committed fixtures follow.
func demoInterfaces() []Interface {
	return []Interface{
		{Name: "eth0", Up: true, IPv4: "198.51.100.20", MAC: "00:00:5e:00:53:10", Role: "wan"},
		{Name: "eth1", Up: true, IPv4: "192.0.2.1", MAC: "00:00:5e:00:53:11", Role: "lan"},
		{Name: "wg0", Up: true, IPv4: "10.0.0.1", Role: "other"},
		{Name: "eth2", Up: false, IPv4: "", MAC: "00:00:5e:00:53:12", Role: "other"},
	}
}

// Name identifies the backend. It calls itself "demo" so a report cannot be
// mistaken for one about a real machine.
func (f *Fake) Name() string { return "demo" }

// Describe is the one-line summary shown in the header.
func (f *Fake) Describe() string { return "demo (a sample office router, nothing is read or changed)" }

// ToolInstalled reports whether a managing tool is present in the demo.
func (f *Fake) ToolInstalled(binary string) bool { return f.installed[binary] }

// Launch refuses in the demo: there is nothing to hand off to, and the demo
// reports every tool absent so this is never reached from the UI.
func (f *Fake) Launch(binary string) (Process, error) {
	return nil, fmt.Errorf("%s is not installed (demo)", binary)
}

// Read returns the sample snapshot. The byte counters advance with real time
// since the demo started, so two successive reads show a live throughput just
// as the real backend would.
func (f *Fake) Read(_ context.Context) (Snapshot, error) {
	now := time.Now()
	elapsed := now.Sub(f.started).Seconds()

	return Snapshot{
		At:         now,
		Interfaces: demoInterfaces(),
		Firewall: FirewallPosture{
			Backend: "nftables", Active: true, Rules: 6, Masquerade: true,
			Summary: "input drop · 6 rules · NAT",
		},
		Counters: []Counter{
			{Name: "eth0", RxBytes: 8_402_850_000 + uint64(elapsed*1_250_000), TxBytes: 3_034_968_000 + uint64(elapsed*420_000)},
			{Name: "eth1", RxBytes: 267_286_000 + uint64(elapsed*180_000), TxBytes: 893_947_000 + uint64(elapsed*640_000)},
			{Name: "wg0", RxBytes: 27_762_000 + uint64(elapsed*24_000), TxBytes: 57_196_000 + uint64(elapsed*36_000)},
		},
		DHCP:    DHCP{Server: "dnsmasq", Active: true, Leases: 12},
		Updates: Updates{Available: true, Pending: 4, Security: 1},
		Roles:   f.readRoles(),
		VPN: VPN{
			Interfaces: []WGInterface{{Name: "wg0", Peers: 3, Handshakes: 2}},
			Headscale:  false,
		},
	}, nil
}
