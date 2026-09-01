package router

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Real is the backend that reads the machine. Every read here is cheap and
// read-only: `ip -j` for the interfaces and routes, /proc/net/dev for the
// counters, the firewall backend's own status command, a lease file's line
// count, and `wg show`. Nothing it does changes the machine — the change
// happens in the tool a card hands off to.
type Real struct {
	ip        *runner.Runner
	wg        *runner.Runner
	nft       *runner.Runner
	ufw       *runner.Runner
	firewalld *runner.Runner
	systemctl *runner.Runner
	// tee, useradd and groupadd are the write side, used only by restore. The
	// reads above never touch them; every mutation the tool makes goes through
	// one of these, so the exec boundary stays a single package.
	tee        *runner.Runner
	useradd    *runner.Runner
	groupadd   *runner.Runner
	procNetDev string
	leasePaths []string
}

// unprivileged and privileged are the address-of values the runner options
// need for PrivilegedReads.
var (
	unprivileged = false
	privileged   = true
)

// procNetDevPath is where the kernel exposes the interface byte counters.
const procNetDevPath = "/proc/net/dev"

// dnsmasqLeasePaths are the places dnsmasq keeps its leases across distributions.
var dnsmasqLeasePaths = []string{
	"/var/lib/misc/dnsmasq.leases",
	"/var/lib/dnsmasq/dnsmasq.leases",
}

// New builds the real backend. sudoPrefix comes from the configuration; the
// reads that need root (the nftables ruleset, ufw status, the WireGuard dump)
// escalate with it, and the ones that do not (ip, firewalld, systemctl) never
// prompt. A backend a machine does not have is simply nil, and its card reads
// "not detected" rather than failing the whole cockpit.
func New(sudoPrefix []string) (*Real, error) {
	r := &Real{procNetDev: procNetDevPath, leasePaths: dnsmasqLeasePaths}

	r.ip, _ = runner.New(runner.Options{
		Bin: "ip", SearchPaths: []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &unprivileged,
		InstallHint: "install it with `apt install iproute2`",
	})
	r.systemctl, _ = runner.New(runner.Options{
		Bin: "systemctl", SearchPaths: []string{"/usr/bin/systemctl", "/bin/systemctl"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &unprivileged,
	})
	r.firewalld, _ = runner.New(runner.Options{
		Bin: "firewall-cmd", SearchPaths: []string{"/usr/bin/firewall-cmd"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &unprivileged,
	})
	r.nft, _ = runner.New(runner.Options{
		Bin: "nft", SearchPaths: []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	r.ufw, _ = runner.New(runner.Options{
		Bin: "ufw", SearchPaths: []string{"/usr/sbin/ufw", "/usr/bin/ufw"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	r.wg, _ = runner.New(runner.Options{
		Bin: "wg", SearchPaths: []string{"/usr/bin/wg", "/bin/wg"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	// The write side, built the same way. A restore escalates every write, so
	// these carry the privilege prefix; a machine that lacks one leaves the
	// runner nil and restore reports it rather than failing halfway.
	r.tee, _ = runner.New(runner.Options{
		Bin: "tee", SearchPaths: []string{"/usr/bin/tee", "/bin/tee"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	r.useradd, _ = runner.New(runner.Options{
		Bin: "useradd", SearchPaths: []string{"/usr/sbin/useradd", "/sbin/useradd"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	r.groupadd, _ = runner.New(runner.Options{
		Bin: "groupadd", SearchPaths: []string{"/usr/sbin/groupadd", "/sbin/groupadd"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &privileged,
	})
	return r, nil
}

// Name identifies the backend.
func (r *Real) Name() string { return "router" }

// Describe is the one-line summary shown in the header.
func (r *Real) Describe() string { return "this machine" }

// ToolInstalled reports whether a managing tool's binary is on PATH.
func (r *Real) ToolInstalled(binary string) bool { return available(binary) }

// Launch hands the terminal to a managing tool.
func (r *Real) Launch(binary string) (Process, error) { return launchBinary(binary) }

// Read takes one snapshot. Each probe is independent: a probe that cannot read
// its part degrades to an empty or unknown value, so the cockpit shows every
// card it can rather than failing on the first one it cannot.
func (r *Real) Read(ctx context.Context) (Snapshot, error) {
	snap := Snapshot{At: time.Now()}
	snap.Interfaces = r.readInterfaces(ctx)
	snap.Counters = r.readCounters()
	snap.Firewall = r.readFirewall(ctx)
	snap.DHCP = r.readDHCP(ctx)
	snap.VPN = r.readVPN(ctx)
	snap.Updates = r.readUpdates(ctx)
	snap.Roles = r.readRoles()
	return snap, nil
}

// readInterfaces reads `ip -j addr` and `ip -j route`.
func (r *Real) readInterfaces(ctx context.Context) []Interface {
	if r.ip == nil {
		return nil
	}
	addr, err := r.ip.Read(ctx, "ip", "-j", "addr")
	if err != nil {
		return nil
	}
	route, _ := r.ip.Read(ctx, "ip", "-j", "route")
	return ParseInterfaces(addr, route)
}

// readCounters reads /proc/net/dev directly: a file read, never a command.
func (r *Real) readCounters() []Counter {
	data, err := os.ReadFile(r.procNetDev)
	if err != nil {
		return nil
	}
	return ParseProcNetDev(string(data))
}

// readFirewall detects the active firewall and reads a one-line posture from
// it. firewalld is preferred because its read is unprivileged; ufw and the raw
// nftables ruleset need root, and a denied escalation becomes a reason rather
// than an error.
func (r *Real) readFirewall(ctx context.Context) FirewallPosture {
	if r.firewalld != nil && r.firewalld.Bin != "" {
		if state, err := r.firewalld.Read(ctx, "firewall-cmd", "--state"); err == nil &&
			strings.Contains(state, "running") {
			out, err := r.firewalld.Read(ctx, "firewall-cmd", "--list-all")
			if err != nil {
				return FirewallPosture{Backend: "firewalld", Active: true, Rules: -1,
					Reason: "could not read the zone"}
			}
			return ParseFirewalldListAll(out)
		}
	}
	if r.ufw != nil && r.ufw.Bin != "" {
		out, err := r.ufw.Read(ctx, "ufw", "status")
		if err != nil {
			return FirewallPosture{Backend: "ufw", Rules: -1, Reason: "needs root to read status"}
		}
		return ParseUfwStatus(out)
	}
	if r.nft != nil && r.nft.Bin != "" {
		out, err := r.nft.Read(ctx, "nft", "list", "ruleset")
		if err != nil {
			return FirewallPosture{Backend: "nftables", Rules: -1, Reason: "needs root to read the ruleset"}
		}
		return ParseNftRuleset(out)
	}
	return FirewallPosture{Rules: -1}
}

// readDHCP detects a DHCP server and counts its leases.
func (r *Real) readDHCP(ctx context.Context) DHCP {
	server, unit := r.detectDHCP()
	if server == "" {
		return DHCP{Leases: -1}
	}
	d := DHCP{Server: server, Leases: -1}
	if r.systemctl != nil && r.systemctl.Bin != "" {
		state, _ := r.systemctl.Read(ctx, "systemctl", "is-active", unit)
		d.Active = strings.TrimSpace(state) == "active"
	}
	if server == "dnsmasq" {
		for _, path := range r.leasePaths {
			if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is one of a fixed set of lease-file locations, never user input
				d.Leases = CountDnsmasqLeases(string(data))
				break
			}
		}
	}
	return d
}

// detectDHCP reports which DHCP server is installed and its unit name.
func (r *Real) detectDHCP() (server, unit string) {
	if runner.Available("dnsmasq", "/usr/sbin/dnsmasq", "/usr/bin/dnsmasq") {
		return "dnsmasq", "dnsmasq.service"
	}
	if runner.Available("kea-dhcp4", "/usr/sbin/kea-dhcp4", "/usr/bin/kea-dhcp4") {
		return "kea", "kea-dhcp4-server.service"
	}
	return "", ""
}

// readVPN reads the WireGuard state and whether headscale is present.
func (r *Real) readVPN(ctx context.Context) VPN {
	v := VPN{Headscale: runner.Available("headscale", "/usr/bin/headscale", "/usr/local/bin/headscale")}
	if r.wg == nil || r.wg.Bin == "" {
		return v
	}
	out, err := r.wg.Read(ctx, "wg", "show", "all", "dump")
	if err != nil {
		v.Reason = "needs root to read the WireGuard state"
		return v
	}
	v.Interfaces = ParseWgDump(out)
	return v
}
