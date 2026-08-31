package router

import (
	"context"
	"fmt"
	"time"
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
}

// NewFake returns the sample router.
func NewFake() *Fake {
	return &Fake{started: time.Now(), installed: map[string]bool{}}
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
		At: now,
		Interfaces: []Interface{
			{Name: "eth0", Up: true, IPv4: "198.51.100.20", Role: "wan"},
			{Name: "eth1", Up: true, IPv4: "192.0.2.1", Role: "lan"},
			{Name: "wg0", Up: true, IPv4: "10.0.0.1", Role: "other"},
			{Name: "eth2", Up: false, IPv4: "", Role: "other"},
		},
		Firewall: FirewallPosture{
			Backend: "nftables", Active: true, Rules: 6, Masquerade: true,
			Summary: "input drop · 6 rules · NAT",
		},
		Counters: []Counter{
			{Name: "eth0", RxBytes: 8_402_850_000 + uint64(elapsed*1_250_000), TxBytes: 3_034_968_000 + uint64(elapsed*420_000)},
			{Name: "eth1", RxBytes: 267_286_000 + uint64(elapsed*180_000), TxBytes: 893_947_000 + uint64(elapsed*640_000)},
			{Name: "wg0", RxBytes: 27_762_000 + uint64(elapsed*24_000), TxBytes: 57_196_000 + uint64(elapsed*36_000)},
		},
		DHCP: DHCP{Server: "dnsmasq", Active: true, Leases: 12},
		VPN: VPN{
			Interfaces: []WGInterface{{Name: "wg0", Peers: 3, Handshakes: 2}},
			Headscale:  false,
		},
	}, nil
}
