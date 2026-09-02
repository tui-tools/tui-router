package router

import (
	"context"
	"os"
	"path/filepath"
	"sort"
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
	// networkctl reads systemd-networkd's own DHCP server: `networkctl status
	// <link>` is where the offered leases are published.
	networkctl *runner.Runner
	// tee, useradd and groupadd are the write side, used only by restore. The
	// reads above never touch them; every mutation the tool makes goes through
	// one of these, so the exec boundary stays a single package.
	tee        *runner.Runner
	useradd    *runner.Runner
	groupadd   *runner.Runner
	procNetDev string
	leasePaths []string
	// networkdDirs are the .network search directories, a field so a test can
	// point the discovery at its own fixtures.
	networkdDirs []string
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
	r := &Real{procNetDev: procNetDevPath, leasePaths: dnsmasqLeasePaths,
		networkdDirs: NetworkdConfigDirs}

	r.ip, _ = runner.New(runner.Options{
		Bin: "ip", SearchPaths: []string{"/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &unprivileged,
		InstallHint: "install it with `apt install iproute2`",
	})
	r.systemctl, _ = runner.New(runner.Options{
		Bin: "systemctl", SearchPaths: []string{"/usr/bin/systemctl", "/bin/systemctl"},
		SudoPrefix: sudoPrefix, PrivilegedReads: &unprivileged,
	})
	r.networkctl, _ = runner.New(runner.Options{
		Bin: "networkctl", SearchPaths: []string{"/usr/bin/networkctl", "/bin/networkctl"},
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
//
// systemd-networkd is looked at first, and only when a .network unit actually
// turns a server on over a real subnet. That is positive evidence — a file
// that says DHCPServer=yes on 192.0.2.1/24 is a server for that LAN —
// whereas dnsmasq and Kea are detected by their binary being installed, which
// a router profile may carry for DNS alone. A machine with both therefore
// reports the one that is serving, and an Omarchy Router, which has no DHCP
// package at all, stops reporting "no DHCP server detected".
func (r *Real) readDHCP(ctx context.Context) DHCP {
	units := r.networkdDHCPUnits()
	for _, unit := range units {
		if unit.Enabled {
			return r.readNetworkdDHCP(ctx, unit)
		}
	}
	if server, unit := detectPackagedDHCP(); server != "" {
		return r.readPackagedDHCP(ctx, server, unit)
	}
	// No package, and no unit that turns the server on: a unit that carries a
	// [DHCPServer] section with the switch off is still worth reporting, as a
	// server configured and stopped rather than nothing at all.
	if len(units) > 0 {
		return r.readNetworkdDHCP(ctx, units[0])
	}
	return DHCP{Leases: -1}
}

// readPackagedDHCP reads the state of dnsmasq or Kea: the unit's activity, and
// for dnsmasq the leases its own lease file lists.
func (r *Real) readPackagedDHCP(ctx context.Context, server, unit string) DHCP {
	d := DHCP{Server: server, Leases: -1}
	d.Active = r.unitActive(ctx, unit)
	if server == ServerDnsmasq {
		for _, path := range r.leasePaths {
			if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path is one of a fixed set of lease-file locations, never user input
				d.Leases = CountDnsmasqLeases(string(data))
				break
			}
		}
	}
	return d
}

// readNetworkdDHCP describes the server one .network unit declares: the link
// it serves, the pool its Address= and PoolOffset=/PoolSize= work out to, and
// the leases networkctl says it has offered.
func (r *Real) readNetworkdDHCP(ctx context.Context, unit NetworkdUnit) DHCP {
	d := DHCP{Server: ServerNetworkd, Leases: -1, Link: unit.Link}
	d.Units = append([]string{unit.Path}, unit.Dropins...)
	if start, end, ok := unit.Pool(); ok {
		d.PoolStart, d.PoolEnd = start, end
	}
	d.Active = unit.Enabled && r.unitActive(ctx, NetworkdUnitName)
	if !d.Active || unit.Link == "" || r.networkctl == nil || r.networkctl.Bin == "" {
		return d
	}
	out, err := r.networkctl.Read(ctx, "networkctl", "status", "--no-pager", unit.Link)
	if err != nil {
		return d
	}
	d.Leases = CountNetworkctlLeases(out)
	return d
}

// unitActive asks systemd whether one unit is running. A machine without
// systemctl simply reports the server as not running rather than failing the
// whole read.
func (r *Real) unitActive(ctx context.Context, unit string) bool {
	if r.systemctl == nil || r.systemctl.Bin == "" {
		return false
	}
	state, _ := r.systemctl.Read(ctx, "systemctl", "is-active", unit)
	return strings.TrimSpace(state) == "active"
}

// detectPackagedDHCP reports which DHCP package is installed and its unit
// name.
func detectPackagedDHCP() (server, unit string) {
	if runner.Available("dnsmasq", "/usr/sbin/dnsmasq", "/usr/bin/dnsmasq") {
		return ServerDnsmasq, "dnsmasq.service"
	}
	if runner.Available("kea-dhcp4", "/usr/sbin/kea-dhcp4", "/usr/bin/kea-dhcp4") {
		return ServerKea, "kea-dhcp4-server.service"
	}
	return "", ""
}

// networkdDHCPUnits reads every .network unit on the machine that declares a
// DHCP server on a subnet of its own, with its drop-ins folded in, in the
// order systemd-networkd reads them: a unit name an earlier search directory
// claims wins, and the drop-ins of that name are applied from every directory,
// /usr/lib first and /etc last — so 50-tui-network-dhcp.conf, which tui-network
// writes under /etc, has the last word on the pool.
//
// A unit a plain read cannot open (netplan renders its files into /run as mode
// 0640) is skipped: the cockpit never escalates for a read it can live
// without.
func (r *Real) networkdDHCPUnits() []NetworkdUnit {
	var units []NetworkdUnit
	seen := map[string]bool{}
	for _, dir := range r.networkdDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, networkSuffix) || seen[name] {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path) //nolint:gosec // the path comes from systemd's own search directories
			if err != nil {
				continue
			}
			files := append([]NetworkdFile{{Path: path, Raw: string(raw)}},
				networkdDropinFiles(r.networkdDirs, name)...)
			unit := ParseNetworkdUnit(files)
			if (unit.HasSection || unit.Enabled) && unit.HasSubnet() {
				units = append(units, unit)
			}
		}
	}
	// Path order, so the unit the card describes is the same on every read.
	sort.Slice(units, func(i, j int) bool { return units[i].Path < units[j].Path })
	return units
}

// networkdDropinFiles reads the drop-ins of one unit name, in networkd's own
// order: the search directories from the most general to the most specific,
// and inside each one the files sorted by name.
func networkdDropinFiles(dirs []string, unitName string) []NetworkdFile {
	var files []NetworkdFile
	for i := len(dirs) - 1; i >= 0; i-- {
		dir := filepath.Join(dirs[i], unitName+".d")
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), dropinSuffix) {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)
		for _, name := range names {
			path := filepath.Join(dir, name)
			raw, err := os.ReadFile(path) //nolint:gosec // the path comes from systemd's own search directories
			if err != nil {
				continue
			}
			files = append(files, NetworkdFile{Path: path, Raw: string(raw)})
		}
	}
	return files
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
