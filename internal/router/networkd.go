package router

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// The DHCP card used to know two servers, dnsmasq and Kea, both detected by
// their binary being installed. An Omarchy Router runs neither: the LAN
// .network unit that omarchy-router-nics writes carries a [DHCPServer]
// section, so systemd-networkd itself hands out the leases. On such a machine
// the card said "no DHCP server detected" while `networkctl status <lan>` was
// listing offered leases.
//
// This file is the pure half of the third server: folding a .network unit and
// its drop-ins the way networkd folds them, working the pool out of Address=
// and PoolOffset=/PoolSize=, and counting the leases networkctl prints. The
// host-facing half — finding the units and running networkctl — lives in
// real.go with the other probes, because that is the tool's only exec site.
//
// The arithmetic and the merge rules follow tui-network's own networkd reader
// (internal/dhcpd/networkd.go), which is the tool this card hands off to; the
// two must describe the same pool. Nothing is imported from it — the cockpit
// depends on no sibling tool — so the shared part is the behaviour, restated
// here against the same fixtures.

// NetworkdConfigDirs are the directories a .network unit can come from, in the
// order systemd-networkd searches them: an earlier one wins the name.
var NetworkdConfigDirs = []string{
	"/etc/systemd/network",
	"/run/systemd/network",
	"/usr/lib/systemd/network",
	"/lib/systemd/network",
}

// networkSuffix is the extension of a .network unit; dropinSuffix is the
// extension of a file inside its <unit>.d/ drop-in directory.
const (
	networkSuffix = ".network"
	dropinSuffix  = ".conf"
)

// NetworkdUnitName is the systemd unit that runs the server, asked about to
// tell a configured server from a running one.
const NetworkdUnitName = "systemd-networkd.service"

// NetworkdFile is one configuration file of a .network unit — the unit itself
// or one of its drop-ins — in the order systemd-networkd reads it.
type NetworkdFile struct {
	Path string
	Raw  string
}

// NetworkdUnit is one .network unit that declares a DHCP server, with its
// drop-ins already folded in: a scalar the last file sets wins, which is how
// 50-tui-network-dhcp.conf changes a pool the unit underneath it declared.
type NetworkdUnit struct {
	// Path is the unit file itself, and Dropins the drop-ins applied over it,
	// in read order.
	Path    string   `json:"path"`
	Dropins []string `json:"dropins,omitempty"`
	// Link is the first Name= pattern of the [Match] section — the interface
	// the server serves, which is also the link the lease read asks about.
	Link string `json:"link,omitempty"`
	// Address is the first [Network] or [Address] Address= with a prefix
	// length: the subnet the pool is carved out of. ServerAddress= in
	// [DHCPServer] wins it when set, which is what networkd itself does.
	Address string `json:"address,omitempty"`
	// Enabled reports DHCPServer=yes in [Network].
	Enabled bool `json:"enabled"`
	// HasSection reports that a [DHCPServer] section exists at all. A unit can
	// have one without DHCPServer=yes, which is a server configured and
	// switched off — worth showing rather than hiding.
	HasSection bool `json:"hasSection"`
	// PoolOffset and PoolSize are the pool keys as written, zero meaning "use
	// the default", exactly as systemd reads them.
	PoolOffset int `json:"poolOffset"`
	PoolSize   int `json:"poolSize"`
}

// HasSubnet reports whether the unit's DHCP server has a subnet this card can
// describe: a concrete IPv4 address with a prefix length.
//
// It is what keeps systemd's own container and VM templates
// (/usr/lib/systemd/network/80-container-ve.network and friends) off the card.
// Those really do run a DHCP server, but on `Address=0.0.0.0/28` — a null
// address systemd fills in per interface — so there is no pool to name.
func (u NetworkdUnit) HasSubnet() bool {
	prefix, err := netip.ParsePrefix(u.Address)
	return err == nil && prefix.Addr().Is4() && !prefix.Addr().IsUnspecified()
}

// Pool is the first and last address this unit's server hands out, or ok=false
// when the unit's keys describe no usable range.
func (u NetworkdUnit) Pool() (start, end string, ok bool) {
	start, end, err := NetworkdPoolRange(u.Address, u.PoolOffset, u.PoolSize)
	return start, end, err == nil
}

// networkdLineRe splits a `Key=value` line, tolerating the spaces systemd
// tolerates.
var networkdLineRe = regexp.MustCompile(`^\s*([A-Za-z0-9_-]+)\s*=(.*)$`)

// networkdSectionRe matches a `[Section]` header.
var networkdSectionRe = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)

// ParseNetworkdUnit folds a unit and its drop-ins, in read order, into one
// NetworkdUnit. files[0] is the unit; the rest are its drop-ins, and a scalar
// a later file assigns replaces the one before it — which is exactly how
// tui-network's 50-tui-network-dhcp.conf moves a pool.
func ParseNetworkdUnit(files []NetworkdFile) NetworkdUnit {
	var unit NetworkdUnit
	if len(files) > 0 {
		unit.Path = files[0].Path
	}
	for i, file := range files {
		if i > 0 {
			unit.Dropins = append(unit.Dropins, file.Path)
		}
		applyNetworkdFile(&unit, file)
	}
	return unit
}

// applyNetworkdFile folds one file's sections over the unit read so far.
func applyNetworkdFile(unit *NetworkdUnit, file NetworkdFile) {
	section := ""
	for _, line := range strings.Split(file.Raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, ";") {
			continue
		}
		if match := networkdSectionRe.FindStringSubmatch(trimmed); match != nil {
			section = strings.ToLower(match[1])
			continue
		}
		match := networkdLineRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		key, value := strings.ToLower(match[1]), strings.TrimSpace(match[2])
		switch section {
		case "match":
			if key == "name" && unit.Link == "" {
				unit.Link = networkdFirstField(value)
			}
		case "network", "address":
			applyNetworkdNetworkKey(unit, key, value)
		case "dhcpserver":
			unit.HasSection = true
			applyNetworkdServerKey(unit, key, value)
		}
	}
}

// applyNetworkdNetworkKey reads the two [Network] (or [Address]) keys the card
// needs: the switch that turns the server on, and the address whose subnet the
// pool is carved out of.
func applyNetworkdNetworkKey(unit *NetworkdUnit, key, value string) {
	switch key {
	case "dhcpserver":
		unit.Enabled = networkdBool(value, false)
	case "address":
		if unit.Address == "" && networkdIsPrefixed(value) {
			unit.Address = value
		}
	}
}

// applyNetworkdServerKey reads the [DHCPServer] keys the pool rests on. Every
// other key of the section (the emit switches, the advertised servers, the
// static leases) belongs to tui-network's editor, not to a read-only card.
func applyNetworkdServerKey(unit *NetworkdUnit, key, value string) {
	switch key {
	case "serveraddress":
		if networkdIsPrefixed(value) {
			unit.Address = value
		}
	case "pooloffset":
		unit.PoolOffset = networkdAtoi(value)
	case "poolsize":
		unit.PoolSize = networkdAtoi(value)
	}
}

// NetworkdPoolRange works out the first and last address a [DHCPServer] hands
// out, from the server address and the PoolOffset=/PoolSize= keys.
//
// The arithmetic is systemd's own (sd_dhcp_server_configure_pool): the pool is
// a run of addresses inside the server address's subnet; offset zero means one
// (the address right after the subnet address) and size zero means the rest of
// the subnet up to but not including the broadcast address. The server's own
// address may fall inside the pool — systemd reserves it and hands out the
// rest — so it is not an error here either.
func NetworkdPoolRange(address string, offset, size int) (start, end string, err error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(address))
	if err != nil || !prefix.Addr().Is4() {
		return "", "", fmt.Errorf(
			"networkd: %q is not an IPv4 address with a prefix length", address)
	}
	if prefix.Addr().IsUnspecified() {
		return "", "", fmt.Errorf(
			"networkd: %s picks its address automatically, so it has no fixed pool",
			address)
	}
	bits := prefix.Bits()
	if bits > 30 {
		return "", "", fmt.Errorf("networkd: /%d leaves no address to hand out", bits)
	}
	// hostCount is systemd's own bound: the host part all ones, i.e. the
	// broadcast address, which the pool must stay below.
	hostCount := (1 << (32 - bits)) - 1
	subnet := prefix.Masked().Addr()

	if offset == 0 {
		offset = 1
	}
	maxSize := hostCount - offset
	if offset < 1 || maxSize < 1 {
		return "", "", fmt.Errorf(
			"networkd: PoolOffset=%d leaves no address in %s", offset, address)
	}
	if size == 0 {
		size = maxSize
	}
	if size < 1 || size > maxSize {
		return "", "", fmt.Errorf(
			"networkd: PoolSize=%d does not fit in %s after PoolOffset=%d",
			size, address, offset)
	}
	return networkdAddrAt(subnet, offset), networkdAddrAt(subnet, offset+size-1), nil
}

// networkdLeasesHeading is the field networkctl prints the DHCP server's
// leases under. It exists since systemd 246; an older systemd simply prints no
// such field and the count comes back zero.
const networkdLeasesHeading = "Offered DHCP leases:"

// networkdLeaseRe reads one entry of that list: `<address> (to <client id>)`,
// which for an Ethernet client is the bare MAC.
var networkdLeaseRe = regexp.MustCompile(`^[0-9a-fA-F.:]+\s+\(to\s+.+\)$`)

// CountNetworkctlLeases counts the leases a link's DHCP server has offered,
// from the text of `networkctl status <link>`. The list is a bus property
// networkctl renders into its table; it is not in the JSON output, so this is
// the read path even on a systemd new enough for --json.
func CountNetworkctlLeases(out string) int {
	count := 0
	inList := false
	for _, line := range strings.Split(out, "\n") {
		value := strings.TrimSpace(line)
		if index := strings.Index(line, networkdLeasesHeading); index >= 0 {
			inList = true
			value = strings.TrimSpace(line[index+len(networkdLeasesHeading):])
		}
		if !inList {
			continue
		}
		if !networkdLeaseRe.MatchString(value) {
			// "none" and the next field of the table both end the list; a
			// blank line inside it does not.
			if value != "" {
				inList = false
			}
			continue
		}
		count++
	}
	return count
}

// networkdBool reads systemd's boolean spelling, falling back for anything
// else.
func networkdBool(value string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "true", "on", "1":
		return true
	case "no", "false", "off", "0":
		return false
	default:
		return fallback
	}
}

// networkdAtoi reads one of the pool integers, returning zero — systemd's own
// "use the default" — for anything that is not a non-negative number.
func networkdAtoi(value string) int {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// networkdFirstField is the first whitespace-separated token of a value, which
// is how a Match Name= with several patterns names the first interface.
func networkdFirstField(value string) string {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// networkdIsPrefixed reports whether a value starts with an IPv4 address that
// carries a prefix length, the only form a server's subnet can be read from.
func networkdIsPrefixed(value string) bool {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return false
	}
	prefix, err := netip.ParsePrefix(fields[0])
	return err == nil && prefix.Addr().Is4()
}

// networkdAddrAt is the address `offset` past a subnet address.
func networkdAddrAt(subnet netip.Addr, offset int) string {
	value := networkdAddrToUint(subnet) + uint32(offset) //nolint:gosec // offset is bounded above by the subnet size
	var octets [4]byte
	binary.BigEndian.PutUint32(octets[:], value)
	return netip.AddrFrom4(octets).String()
}

// networkdAddrToUint is the address as the number the offsets are counted in.
func networkdAddrToUint(addr netip.Addr) uint32 {
	b := addr.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
