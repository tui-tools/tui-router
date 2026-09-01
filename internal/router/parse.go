package router

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file holds the pure text-to-struct parsers: bytes another program
// wrote, on a machine we have never seen, turned into the values the cards
// show. Every one of them carries a fuzz target in fuzz_test.go, and every one
// degrades a shape it does not recognise into an empty result rather than a
// panic or an invented value.

// ipAddr mirrors the fields of `ip -j addr` this tool reads.
type ipAddr struct {
	IfName    string   `json:"ifname"`
	Flags     []string `json:"flags"`
	OperState string   `json:"operstate"`
	LinkType  string   `json:"link_type"`
	Address   string   `json:"address"`
	AddrInfo  []struct {
		Family string `json:"family"`
		Local  string `json:"local"`
		Scope  string `json:"scope"`
	} `json:"addr_info"`
}

// ipRoute mirrors the fields of `ip -j route` this tool reads.
type ipRoute struct {
	Dst   string `json:"dst"`
	Dev   string `json:"dev"`
	Scope string `json:"scope"`
}

// ParseLinkNames turns `ip -j link` into the plain list of interface names
// this machine carries. It is what a restore compares an artifact's roles.conf
// against: the loopback is dropped, because no role is ever assigned to it. A
// payload it cannot read yields no names, and the caller says the comparison
// was not possible rather than claiming the names matched.
func ParseLinkNames(linkJSON string) []string {
	var links []ipAddr
	if err := json.Unmarshal([]byte(linkJSON), &links); err != nil {
		return nil
	}
	out := make([]string, 0, len(links))
	for _, l := range links {
		if l.IfName == "" || l.IfName == "lo" {
			continue
		}
		out = append(out, l.IfName)
	}
	return out
}

// ParseInterfaces turns `ip -j addr` and `ip -j route` into the interface
// list, tagging each interface's role from the routing table: an interface
// carrying a default route is WAN, one with a directly attached subnet is LAN,
// everything else (loopback, unrouted tunnels) is other.
func ParseInterfaces(addrJSON, routeJSON string) []Interface {
	var addrs []ipAddr
	if err := json.Unmarshal([]byte(addrJSON), &addrs); err != nil {
		return nil
	}
	var routes []ipRoute
	// A route table that will not parse is not fatal: roles fall back to LAN
	// or other, but the interfaces themselves are still worth showing.
	_ = json.Unmarshal([]byte(routeJSON), &routes)

	wan := map[string]bool{}
	lan := map[string]bool{}
	for _, r := range routes {
		if r.Dev == "" {
			continue
		}
		if r.Dst == "default" {
			wan[r.Dev] = true
			continue
		}
		// A link-scope route to a real subnet marks an attached LAN. A host
		// route (no slash) or a route to a single address is not a subnet.
		if r.Scope == "link" && strings.Contains(r.Dst, "/") {
			lan[r.Dev] = true
		}
	}

	out := make([]Interface, 0, len(addrs))
	for _, a := range addrs {
		if a.IfName == "" {
			continue
		}
		iface := Interface{
			Name: a.IfName,
			Up:   interfaceUp(a),
			IPv4: firstGlobalIPv4(a),
			MAC:  strings.ToLower(a.Address),
			Role: role(a, wan, lan),
		}
		out = append(out, iface)
	}
	return out
}

// interfaceUp reports whether the link is usable: administratively up and not
// operationally down. A WireGuard interface reports operstate UNKNOWN while
// being up, so only an explicit DOWN counts against it.
func interfaceUp(a ipAddr) bool {
	admin := false
	for _, f := range a.Flags {
		if f == "UP" {
			admin = true
			break
		}
	}
	return admin && a.OperState != "DOWN"
}

// firstGlobalIPv4 returns the first globally scoped IPv4 address, which is the
// one a reader wants to see; a host or link address is not it.
func firstGlobalIPv4(a ipAddr) string {
	for _, info := range a.AddrInfo {
		if info.Family == "inet" && info.Scope != "host" && info.Scope != "link" {
			return info.Local
		}
	}
	return ""
}

// role tags an interface WAN, LAN or other from the route maps.
func role(a ipAddr, wan, lan map[string]bool) string {
	switch {
	case a.LinkType == "loopback":
		return "other"
	case wan[a.IfName]:
		return "wan"
	case a.LinkType == "none":
		// A tunnel (WireGuard, tun) has no link-layer address. Its own card
		// (VPN) covers it; on the interfaces card it is neither WAN nor LAN
		// even when it carries an attached subnet.
		return "other"
	case lan[a.IfName]:
		return "lan"
	default:
		return "other"
	}
}

// updateCheck mirrors the two counts this tool reads from the JSON document
// `tui-update --check` prints. Pointers tell a missing field from a zero, so
// a document of the wrong shape is refused rather than read as "up to date".
type updateCheck struct {
	Pending      *int   `json:"pending"`
	Security     *int   `json:"security"`
	PendingError string `json:"pendingError"`
}

// ParseUpdateCheck reads the pending/security counts from another program's
// JSON, defensively: a document that is not JSON, lacks the counts, carries a
// negative count, or reports its own read failed comes back not-ok with a
// reason, never as an invented number.
func ParseUpdateCheck(text string) Updates {
	var doc updateCheck
	if err := json.Unmarshal([]byte(text), &doc); err != nil {
		return Updates{Reason: "unreadable tui-update --check output"}
	}
	if doc.PendingError != "" {
		return Updates{Reason: doc.PendingError}
	}
	if doc.Pending == nil {
		return Updates{Reason: "tui-update --check reported no pending count"}
	}
	u := Updates{Available: true, Pending: *doc.Pending}
	if doc.Security != nil {
		u.Security = *doc.Security
	}
	if u.Pending < 0 || u.Security < 0 {
		return Updates{Reason: "tui-update --check reported a negative count"}
	}
	return u
}

// ParseProcNetDev turns /proc/net/dev into per-interface byte counters. The
// file has two header lines and then `iface: rx-bytes rx-packets … tx-bytes …`
// per interface, with the colon sometimes glued to the name.
func ParseProcNetDev(text string) []Counter {
	var out []Counter
	for _, line := range strings.Split(text, "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			// The two header lines carry a `|`, not a `:`.
			continue
		}
		name = strings.TrimSpace(name)
		// A real interface name is a single bare token. Anything with internal
		// whitespace or a table-drawing character came from a header or a
		// mangled line, not an interface.
		if name == "" || strings.ContainsAny(name, " \t\n\r\v\f|") {
			continue
		}
		fields := strings.Fields(rest)
		// Receive is the first block of 8 columns, Transmit the next: bytes
		// are columns 0 and 8.
		if len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, Counter{Name: name, RxBytes: rx, TxBytes: tx})
	}
	return out
}

// ParseWgDump turns `wg show all dump` into the WireGuard interface list. The
// first line of each interface is `iface private public listen fwmark`; each
// following line with the same interface name is a peer, and its 5th field is
// the latest-handshake timestamp (0 means never).
func ParseWgDump(text string) []WGInterface {
	order := []string{}
	byName := map[string]*WGInterface{}
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) == 0 || fields[0] == "" {
			continue
		}
		name := fields[0]
		iface, seen := byName[name]
		if !seen {
			iface = &WGInterface{Name: name}
			byName[name] = iface
			order = append(order, name)
		}
		// An interface header has 5 fields; a peer line has more (endpoint,
		// allowed-ips, handshake, rx, tx, keepalive). The header is not a peer.
		if len(fields) < 6 {
			continue
		}
		iface.Peers++
		// A peer line is: interface, public-key, preshared-key, endpoint,
		// allowed-ips, latest-handshake, rx, tx, keepalive. Field 6 (0-indexed
		// 5) is the latest handshake unix time; non-zero is an established peer.
		if hs, err := strconv.ParseInt(fields[5], 10, 64); err == nil && hs > 0 {
			iface.Handshakes++
		}
	}
	out := make([]WGInterface, 0, len(order))
	for _, name := range order {
		out = append(out, *byName[name])
	}
	return out
}

// CountDnsmasqLeases counts the current leases in a dnsmasq leases file. Each
// lease is one line whose first field is the expiry (a number, or 0 for an
// infinite lease); a blank or malformed line is not a lease.
func CountDnsmasqLeases(text string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		// A lease line is `expiry mac ip host clientid`: at least four fields,
		// the first a number.
		if len(fields) < 4 {
			continue
		}
		if _, err := strconv.ParseInt(fields[0], 10, 64); err != nil {
			continue
		}
		n++
	}
	return n
}

// ParseFirewalldListAll reads a firewalld zone from `firewall-cmd --list-all`.
// It is an unprivileged read, so it is the cheapest firewall posture the
// cockpit can take.
func ParseFirewalldListAll(text string) FirewallPosture {
	p := FirewallPosture{Backend: "firewalld", Active: true, Rules: 0}
	rules := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "masquerade:"):
			p.Masquerade = strings.TrimSpace(strings.TrimPrefix(line, "masquerade:")) == "yes"
		case strings.HasPrefix(line, "services:"):
			rules += len(strings.Fields(strings.TrimPrefix(line, "services:")))
		case strings.HasPrefix(line, "ports:"):
			rules += len(strings.Fields(strings.TrimPrefix(line, "ports:")))
		case strings.HasPrefix(line, "rich rules:"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "rich rules:"))
			if rest != "" {
				rules++
			}
		}
	}
	p.Rules = rules
	summary := strconv.Itoa(rules) + " openings"
	if p.Masquerade {
		summary += " · NAT"
	}
	p.Summary = summary
	return p
}

// ParseNftRuleset reads the nftables ruleset from `nft list ruleset`, counting
// rules and reading the input chain's policy and whether any chain masquerades.
func ParseNftRuleset(text string) FirewallPosture {
	p := FirewallPosture{Backend: "nftables", Active: true, Rules: 0}
	inputPolicy := ""
	rules := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "table ") ||
			strings.HasPrefix(line, "chain ") || line == "}":
			// Structure, not a rule.
		case strings.HasPrefix(line, "type filter hook input"):
			if i := strings.Index(line, "policy "); i >= 0 {
				inputPolicy = strings.TrimRight(strings.TrimSpace(line[i+len("policy "):]), ";")
			}
		case strings.HasPrefix(line, "type "):
			// A chain declaration line (hook/policy) is not a rule.
		default:
			rules++
			if strings.Contains(line, "masquerade") {
				p.Masquerade = true
			}
		}
	}
	p.Rules = rules
	summary := ""
	if inputPolicy != "" {
		summary = "input " + inputPolicy + " · "
	}
	summary += strconv.Itoa(rules) + " rules"
	if p.Masquerade {
		summary += " · NAT"
	}
	p.Summary = summary
	return p
}

// ParseUfwStatus reads ufw's posture from `ufw status`. The header line says
// active or inactive, and each numbered/allow/deny line below is a rule.
func ParseUfwStatus(text string) FirewallPosture {
	p := FirewallPosture{Backend: "ufw", Rules: 0}
	rules := 0
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Status:"):
			p.Active = strings.Contains(line, "active")
		case line == "" || strings.HasPrefix(line, "To ") || strings.HasPrefix(line, "--"):
			// Header and separators.
		case strings.Contains(line, "ALLOW") || strings.Contains(line, "DENY") ||
			strings.Contains(line, "REJECT") || strings.Contains(line, "LIMIT"):
			rules++
		}
	}
	p.Rules = rules
	if p.Active {
		p.Summary = "active · " + strconv.Itoa(rules) + " rules"
	} else {
		p.Summary = "inactive"
	}
	return p
}
