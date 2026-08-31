// Package backup is the pure core of tui-router's single-artifact
// backup/restore (item 15, stage 1). It turns the router's logical identity
// into one self-describing, integrity-checked file and back again, and it does
// so without ever touching the machine: no exec, no clock, no randomness. Every
// timestamp and default filename is passed in from the command layer, so the
// package is deterministic and its readers are fuzzable.
//
// The artifact is a gzip'd tar (".tuiback") that carries a manifest, one part
// per subsystem, an always-present checksum file, and an optional detached
// signature. Integrity (the checksums) is unconditional; a signature is added
// only when the operator supplies a key. No secret is ever written into the
// artifact: WireGuard key material is referenced by path and stripped from the
// serialized config, and accounts carry names and roles only.
package backup

// SchemaVersion is the artifact schema this build reads and writes. A restore
// refuses a schema it does not understand rather than guessing at a layout.
const SchemaVersion = 1

// Extension is the artifact's file extension.
const Extension = ".tuiback"

// The relative paths of the fixed files inside the tar. Everything else lives
// under partsDir with a subsystem-specific name.
const (
	manifestPath  = "manifest.json"
	checksumPath  = "MANIFEST.sha256"
	signaturePath = "SIGNATURE"
	partsDir      = "parts/"
)

// Subsystem tags label each part with the router area it captures. They are a
// fixed set: an unknown tag in an artifact is data the restore does not know
// how to apply, and it is surfaced rather than run.
const (
	SubsystemNftables  = "nftables"
	SubsystemNetworkd  = "networkd"
	SubsystemDHCPDNS   = "dhcp-dns"
	SubsystemWireguard = "wireguard"
	SubsystemAccounts  = "accounts"
)

// The fixed part paths for the single-file subsystems.
const (
	nftablesPart = partsDir + "nftables.rules"
	dhcpDNSPart  = partsDir + "dhcp-dns.conf"
	accountsPart = partsDir + "accounts.json"
	networkdDir  = partsDir + "networkd/"
	wireguardDir = partsDir + "wireguard/"
)

// Account is one router-owned user or group the profile provisions. Stage 1
// captures the name and role only: credential hashes are explicitly out of
// scope and are never read into an artifact.
type Account struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// WGConf is one WireGuard interface as the artifact carries it: the serialized
// config with every key line stripped, plus the path where the operator keeps
// the interface's key material. The material itself is restored out of band and
// never travels in the artifact.
type WGConf struct {
	// Config is the interface configuration with all key material removed.
	Config string `json:"config"`
	// KeyRef is the on-disk path the stripped key line pointed at, kept as a
	// slot so a restore can tell the operator which file to provision by hand.
	KeyRef string `json:"keyRef,omitempty"`
}

// Sources is the router's logical identity: the exact bytes each subsystem
// needs to be reproduced, already scrubbed of secrets. It is what export
// serializes and what restore applies, and two Sources compare equal exactly
// when they describe the same router — which is what the round-trip test rests
// on.
type Sources struct {
	// Nftables is the serialized ruleset, the plain form `nft -f` re-loads
	// (never the -j JSON, which nft cannot reload directly).
	Nftables string `json:"nftables"`
	// Networkd maps a unit's base filename to its content: the .network/.link
	// units that define the WAN/LAN roles.
	Networkd map[string]string `json:"networkd,omitempty"`
	// DHCPDNS is the dnsmasq (or dhcpd) config the router profile owns.
	DHCPDNS string `json:"dhcpDNS,omitempty"`
	// Wireguard maps an interface name to its stripped config and key slot.
	Wireguard map[string]WGConf `json:"wireguard,omitempty"`
	// Accounts is the router's own users/groups, names and roles only.
	Accounts []Account `json:"accounts,omitempty"`
}

// Meta is the identity of one export, all of it passed in from the command
// layer so the pure package never reads a clock or a hostname it cannot
// reproduce in a test.
type Meta struct {
	// ToolVersion is the tui-router version that wrote the artifact.
	ToolVersion string
	// Hostname is the machine the export was taken from.
	Hostname string
	// Timestamp is the UTC time of the export, formatted by the caller.
	Timestamp string
}

// Part is one entry in the manifest: where the bytes live in the tar, which
// subsystem they belong to, their size and their SHA-256. The checksum is what
// a verify recomputes and compares.
type Part struct {
	Path      string `json:"path"`
	Subsystem string `json:"subsystem"`
	Bytes     int    `json:"bytes"`
	SHA256    string `json:"sha256"`
}

// Manifest is the artifact's table of contents: the schema and tool versions,
// the export identity, the parts, and the WireGuard key slots. It is itself
// covered by MANIFEST.sha256, so tampering with it is caught like tampering
// with any part.
type Manifest struct {
	Schema      int    `json:"schema"`
	ToolVersion string `json:"toolVersion"`
	Hostname    string `json:"hostname"`
	Timestamp   string `json:"timestamp"`
	Parts       []Part `json:"parts"`
	// WireguardKeyRefs maps an interface name to the on-disk key path the
	// stripped config pointed at. The path is a reference, never the material.
	WireguardKeyRefs map[string]string `json:"wireguardKeyRefs,omitempty"`
}
