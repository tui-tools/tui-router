// Package router is the read-only cockpit of the tui-tools family: it reads a
// router's state from cheap system probes, shows it as one card per area, and
// hands the terminal to the tool that manages each area. It changes nothing
// itself — every mutation happens in the tool a card launches.
//
// This is the only package in the tool that starts a process, which is what
// the family's exec boundary requires (tui-kit/tools/check-exec.sh): the
// read-only probes and the handoff exec both live here, nowhere else.
package router

import (
	"context"
	"io"
	"time"
)

// CardKind identifies one panel of the cockpit. The order here is the order
// the cards are drawn, so the reader learns where each one sits.
type CardKind string

// The cockpit's cards, in display order.
const (
	CardInterfaces CardKind = "interfaces"
	CardFirewall   CardKind = "firewall"
	CardTraffic    CardKind = "traffic"
	CardDHCP       CardKind = "dhcp"
	CardVPN        CardKind = "vpn"
	CardUpdates    CardKind = "updates"
)

// Kinds is the fixed card order. A card that moved between reads would be a
// card nobody could learn the position of.
var Kinds = []CardKind{CardInterfaces, CardFirewall, CardTraffic, CardDHCP, CardVPN, CardUpdates}

// Status is a card's verdict, used only to colour it. A cockpit reports, it
// does not grade a machine, so the palette is deliberately small: ok for a
// healthy reading, warn for one that wants a look, info for a neutral fact,
// and unknown for a read that could not be made (a missing binary, a denied
// privilege) — never an error that stops the screen.
type Status string

// The verdicts.
const (
	StatusOK      Status = "ok"
	StatusWarn    Status = "warn"
	StatusInfo    Status = "info"
	StatusUnknown Status = "unknown"
)

// Interface is one network interface as the cockpit reads it.
type Interface struct {
	Name string `json:"name"`
	// Up reports whether the link is operationally up.
	Up bool `json:"up"`
	// IPv4 is the first global IPv4 address, empty when there is none.
	IPv4 string `json:"ipv4,omitempty"`
	// MAC is the link-layer address, lower-case, empty when the interface has
	// none (a tunnel). The roles wizard uses it for by-MAC pinning.
	MAC string `json:"mac,omitempty"`
	// Role is "wan" for the interface carrying a default route, "lan" for one
	// with a directly attached subnet, "other" otherwise (loopback, tunnels).
	Role string `json:"role"`
}

// FirewallPosture is the one-line summary of the active firewall.
type FirewallPosture struct {
	// Backend is the firewall in charge: "firewalld", "nftables", "ufw" or ""
	// when none is present.
	Backend string `json:"backend,omitempty"`
	// Active reports whether that backend is running/enforcing.
	Active bool `json:"active"`
	// Summary is a short human posture line, e.g. "input drop · 6 rules".
	Summary string `json:"summary,omitempty"`
	// Rules is the rule count the posture rests on, -1 when it could not be
	// read (an unprivileged run of a backend whose read needs root).
	Rules int `json:"rules"`
	// Masquerade reports NAT masquerade being configured, when it is known.
	Masquerade bool `json:"masquerade"`
	// Reason is why the posture is unknown, when it is.
	Reason string `json:"reason,omitempty"`
}

// Counter is one interface's cumulative byte counters, read from
// /proc/net/dev. The cockpit turns two readings into a throughput.
type Counter struct {
	Name    string `json:"name"`
	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
}

// Throughput is the per-interface rate derived from two Counter readings.
type Throughput struct {
	Name string `json:"name"`
	// RxBps and TxBps are bytes per second over the interval between readings.
	RxBps float64 `json:"rxBps"`
	TxBps float64 `json:"txBps"`
}

// DHCP is the state of a DHCP server on this machine.
type DHCP struct {
	// Server is "dnsmasq", "kea" or "" when none is present.
	Server string `json:"server,omitempty"`
	// Active reports whether the server unit is running.
	Active bool `json:"active"`
	// Leases is the number of current leases, -1 when the lease file could
	// not be read.
	Leases int `json:"leases"`
	// Reason is why the state is unknown, when it is.
	Reason string `json:"reason,omitempty"`
}

// WGInterface is one WireGuard interface and how many peers it carries.
type WGInterface struct {
	Name  string `json:"name"`
	Peers int    `json:"peers"`
	// Handshakes is the number of peers with a recent handshake.
	Handshakes int `json:"handshakes"`
}

// VPN is the WireGuard and control-plane state.
type VPN struct {
	Interfaces []WGInterface `json:"interfaces,omitempty"`
	// Headscale reports whether a headscale control plane is present on this
	// machine.
	Headscale bool `json:"headscale"`
	// Reason is why the state is unknown, when it is.
	Reason string `json:"reason,omitempty"`
}

// Updates is the pending-updates state, read from `tui-update --check`.
type Updates struct {
	// Available reports whether the check could run at all; when it is false,
	// Reason says why (the binary is absent, or the check failed).
	Available bool `json:"available"`
	// Pending and Security are the counts the check reported.
	Pending  int `json:"pending"`
	Security int `json:"security"`
	// Reason is why the state is unknown, when it is.
	Reason string `json:"reason,omitempty"`
}

// Snapshot is one read of the whole machine: everything the cards are built
// from, taken as close together in time as the probes allow.
type Snapshot struct {
	Interfaces []Interface     `json:"interfaces"`
	Firewall   FirewallPosture `json:"firewall"`
	Counters   []Counter       `json:"-"`
	DHCP       DHCP            `json:"dhcp"`
	VPN        VPN             `json:"vpn"`
	Updates    Updates         `json:"updates"`
	// Roles is the router profile's WAN/LAN role assignment state, which is
	// what decides whether the cockpit offers the roles wizard.
	Roles RolesStatus `json:"roles"`
	// At is when the counters were read, so a throughput can be derived from
	// two snapshots.
	At time.Time `json:"-"`
}

// CardTool names the family tool that manages each card's area. ENTER on a
// card hands the terminal to this tool when it is installed.
var CardTool = map[CardKind]string{
	CardInterfaces: "tui-network",
	CardFirewall:   "tui-firewall",
	CardTraffic:    "tui-traffic",
	CardDHCP:       "tui-network",
	CardVPN:        "tui-vpn",
	CardUpdates:    "tui-update",
}

// Card is one rendered panel: a title, a verdict, a headline and the detail
// lines under it, plus the tool that manages the area and whether it is here.
type Card struct {
	Kind    CardKind `json:"kind"`
	Title   string   `json:"title"`
	Status  Status   `json:"status"`
	Summary string   `json:"summary"`
	Lines   []string `json:"lines,omitempty"`
	// Tool is the managing tool's binary name.
	Tool string `json:"tool"`
	// ToolInstalled reports whether that binary is on PATH, so ENTER either
	// launches it or says it is not here — never anything destructive.
	ToolInstalled bool `json:"toolInstalled"`
}

// Backend is the boundary between the cockpit and the machine. Read takes one
// snapshot; ToolInstalled answers whether a managing tool is present; Launch
// hands the terminal to one. There is no method that mutates the machine: a
// cockpit is read-only, and the tools it launches own every change.
type Backend interface {
	// Name identifies the backend ("router", "demo").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string
	// Read takes one snapshot of the whole machine.
	Read(ctx context.Context) (Snapshot, error)
	// ToolInstalled reports whether a managing tool's binary is on PATH.
	ToolInstalled(binary string) bool
	// Launch hands the terminal to a managing tool for a suspend-run-resume
	// handoff. It returns a Process the UI passes to tea.Exec.
	Launch(binary string) (Process, error)
}

// Process is what tea.Exec drives: the child tool that takes over the
// terminal while the cockpit is suspended. Its method set is exactly Bubble
// Tea's tea.ExecCommand, so the value goes straight to tea.Exec.
type Process interface {
	Run() error
	SetStdin(io.Reader)
	SetStdout(io.Writer)
	SetStderr(io.Writer)
}
