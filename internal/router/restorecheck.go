package router

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/tui-tools/tui-router/internal/backup"
)

// This file is the restore's content gate. An artifact is bytes from another
// machine (or from a file someone could have edited at rest), and every file a
// restore writes is read by something that runs as root: bash sources
// roles.conf, wg-quick runs hooks, dnsmasq runs scripts and reads other files,
// sysctl --system can hand the kernel a program to run. Checksums and even a
// signature only say who wrote the bytes, not that the bytes are harmless.
//
// The policy, per file type, is the same: a directive that runs a command or
// loads code or config from another path is refused, unless it is one of the
// exact forms this tool family writes itself, and then only in that exact form.
// Every refusal names the file the line would land in, its line number and the
// line, so the preview can show the operator precisely what blocked the
// restore.

// RestoreFinding is one thing in an artifact that a restore refuses to write.
type RestoreFinding struct {
	// File is the on-disk path the content would be written to, or a label
	// for a part that is not a file (the live ruleset, the accounts).
	File string
	// Line is the 1-based line number in that content, 0 when the finding is
	// about the part as a whole (an unsafe name).
	Line int
	// Text is the offending line, trimmed, empty for a whole-part finding.
	Text string
	// Reason says, in a few words, why the line is refused.
	Reason string
}

// String renders a finding as "file:line: reason" followed by the line.
func (f RestoreFinding) String() string {
	loc := f.File
	if f.Line > 0 {
		loc = fmt.Sprintf("%s:%d", f.File, f.Line)
	}
	if f.Text == "" {
		return loc + ": " + f.Reason
	}
	return loc + ": " + f.Reason + "\n    " + f.Text
}

// RestoreRefusedError is the error a restore returns when the artifact carries
// findings. It lists every one of them, so the message alone is enough to see
// what to fix.
type RestoreRefusedError struct {
	Findings []RestoreFinding
}

func (e *RestoreRefusedError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "restore refused: the artifact carries %d line(s) that would run a command "+
		"or load files from elsewhere as root:", len(e.Findings))
	for _, f := range e.Findings {
		b.WriteString("\n  " + f.String())
	}
	return b.String()
}

// Labels for the parts that are not written to a config file.
const (
	nftablesLabel = "nftables ruleset (applied with nft -f)"
	accountsLabel = "accounts"
)

// CheckRestore runs the content gate over every part an artifact carries and
// returns the findings in a stable order: the single-file parts in the order a
// restore writes them, then the multi-file parts by name, then the ruleset and
// the accounts. An empty result means the restore may proceed.
func CheckRestore(src backup.Sources) []RestoreFinding {
	var out []RestoreFinding
	for _, single := range []struct{ subsystem, content string }{
		{backup.SubsystemRoles, src.Roles},
		{backup.SubsystemSysctl, src.Sysctl},
		{backup.SubsystemResolved, src.Resolved},
		{backup.SubsystemFirewallRules, src.FirewallRules},
		{backup.SubsystemDHCPDNS, src.DHCPDNS},
	} {
		out = append(out, CheckConfigPart(single.subsystem, "", single.content)...)
	}
	for _, name := range sortedStringKeys(src.Networkd) {
		out = append(out, CheckConfigPart(backup.SubsystemNetworkd, name, src.Networkd[name])...)
	}
	for _, name := range sortedWireguardNames(src.Wireguard) {
		out = append(out, CheckConfigPart(backup.SubsystemWireguard, name, src.Wireguard[name].Config)...)
	}
	out = append(out, checkNftables(nftablesLabel, src.Nftables)...)
	out = append(out, checkAccounts(src.Accounts)...)
	return out
}

// CheckConfigPart runs the gate over one config-file part, the unit the
// backend writes. Empty content is not written, so it has nothing to refuse.
func CheckConfigPart(subsystem, name, content string) []RestoreFinding {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	label, err := configPath(subsystem, name)
	if err != nil {
		return []RestoreFinding{{File: subsystem + "/" + name, Reason: err.Error()}}
	}
	switch subsystem {
	case backup.SubsystemRoles:
		return rolesFindings(label, content)
	case backup.SubsystemSysctl:
		return sysctlFindings(label, content)
	case backup.SubsystemDHCPDNS:
		return dnsmasqFindings(label, content)
	case backup.SubsystemWireguard:
		if !validWireguardName(name) {
			return []RestoreFinding{{File: label,
				Reason: fmt.Sprintf("%q is not a WireGuard interface name wg-quick accepts", name)}}
		}
		return wireguardFindings(label, name, content)
	case backup.SubsystemNetworkd:
		// networkd units carry no directive that runs a command or includes
		// another file. What the gate pins is the name: only the unit kinds
		// the collector reads may be written into /etc/systemd/network.
		if !hasAnySuffix(name, networkdSuffixes) {
			return []RestoreFinding{{File: label,
				Reason: "not a .network or .link unit, the only kinds an export carries"}}
		}
		return nil
	case backup.SubsystemFirewallRules:
		return checkNftables(label, content)
	case backup.SubsystemResolved:
		// systemd-resolved drop-ins name DNS servers and switches; there is
		// no key that runs a program or reads another file.
		return nil
	}
	return []RestoreFinding{{File: label, Reason: "no content check exists for subsystem " + subsystem}}
}

// networkdSuffixes are the unit kinds CollectSources reads from
// /etc/systemd/network, and therefore the only ones a restore writes.
var networkdSuffixes = []string{".network", ".link"}

// configLines walks content line by line and calls fn with the 1-based line
// number, the raw line and the line trimmed of surrounding blanks. Blank lines
// are skipped.
func configLines(content string, fn func(n int, trimmed string)) {
	for i, raw := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		fn(i+1, trimmed)
	}
}

// --- roles.conf --------------------------------------------------------------

// rolesSetKeys are the role-set keys the roles wizard writes (and the singular
// forms the profile's seed file and parser also accept), each with the shape
// every member of its value must have.
var rolesSetKeys = map[string]func(string) bool{
	"WAN_IFS":  ValidIfaceName,
	"WAN_IF":   ValidIfaceName,
	"LAN_IFS":  ValidIfaceName,
	"LAN_IF":   ValidIfaceName,
	"WAN_MACS": validMACAnyCase,
	"WAN_MAC":  validMACAnyCase,
	"LAN_MACS": validMACAnyCase,
	"LAN_MAC":  validMACAnyCase,
}

// rolesKnobKeys are the two other keys the router profile reads from
// roles.conf (network-router.sh), each with its value validator. An empty
// value is legal for both: the profile then uses its default.
var rolesKnobKeys = map[string]func(string) bool{
	"LAN_ADDRESS": validLANAddress,
	"LAN_DHCP":    func(v string) bool { return v == "yes" || v == "no" },
}

// validMACAnyCase is ValidMAC for a value the parser will lower-case.
func validMACAnyCase(mac string) bool { return ValidMAC(strings.ToLower(mac)) }

// validLANAddress accepts the gateway address in CIDR form, the shape the
// profile writes into the LAN unit's Address=.
func validLANAddress(v string) bool {
	_, err := netip.ParsePrefix(v)
	return err == nil
}

// rolesValue reads the value half of a roles.conf assignment the way bash
// would, refusing anything whose meaning to bash is more than a plain string:
// a value is either bare with no blank in it (a blank there would make bash run
// the rest of the line as a command), or wrapped in one pair of matching
// quotes with no quote inside.
func rolesValue(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	if raw[0] == '"' || raw[0] == '\'' {
		q := raw[0]
		if len(raw) < 2 || raw[len(raw)-1] != q {
			return "", false
		}
		inner := raw[1 : len(raw)-1]
		if strings.ContainsAny(inner, "\"'") {
			return "", false
		}
		return inner, true
	}
	if strings.ContainsAny(raw, " \t\"'") {
		return "", false
	}
	return raw, true
}

// rolesFindings checks roles.conf against an allowlist: comments, blanks, and
// assignments of exactly the keys the wizard and the profile use, each value
// validated member by member. Anything else — another variable (PATH,
// LD_PRELOAD, BASH_ENV…), a command, a function — is refused, because the file
// is sourced by bash as root and any line in it is code.
func rolesFindings(file, content string) []RestoreFinding {
	var out []RestoreFinding
	configLines(content, func(n int, line string) {
		if strings.HasPrefix(line, "#") {
			return
		}
		refuse := func(reason string) {
			out = append(out, RestoreFinding{File: file, Line: n, Text: line, Reason: reason})
		}
		m := rolesLine.FindStringSubmatch(line)
		if m == nil {
			refuse("not a KEY=value assignment; roles.conf is sourced by bash, so any other line is a command")
			return
		}
		key := m[1]
		value, ok := rolesValue(m[2])
		if !ok {
			refuse("the value is not a plain quoted string")
			return
		}
		if valid, isSet := rolesSetKeys[key]; isSet {
			for _, member := range strings.Fields(value) {
				if !valid(member) {
					refuse(fmt.Sprintf("%q is not a valid member of %s", member, key))
					return
				}
			}
			return
		}
		if valid, isKnob := rolesKnobKeys[key]; isKnob {
			if value != "" && !valid(value) {
				refuse(fmt.Sprintf("%q is not a valid value for %s", value, key))
			}
			return
		}
		refuse(key + " is not a key tui-router or the router profile writes to roles.conf")
	})
	return out
}

// canonicalRolesKnobs renders the allowlisted knob lines of a roles.conf that
// already passed rolesFindings, in file order and in the one canonical form
// (KEY="value"), so what a restore writes is never the artifact's bytes.
func canonicalRolesKnobs(content string) []string {
	var out []string
	configLines(content, func(_ int, line string) {
		m := rolesLine.FindStringSubmatch(line)
		if m == nil {
			return
		}
		if _, isKnob := rolesKnobKeys[m[1]]; !isKnob {
			return
		}
		value, _ := rolesValue(m[2])
		out = append(out, fmt.Sprintf("%s=%q", m[1], value))
	})
	return out
}

// --- sysctl ------------------------------------------------------------------

// sysctlProgramKeys are the kernel knobs whose value names a program the
// kernel runs as root (or, for core_pattern, a pipe to one).
var sysctlProgramKeys = map[string]bool{
	"kernel.core_pattern": true,
	"kernel.modprobe":     true,
	"kernel.hotplug":      true,
	"kernel.poweroff_cmd": true,
	"kernel.reboot_cmd":   true,
}

// sysctlKey normalises a sysctl.d key the way systemd-sysctl and procps read
// it: a leading "-" only silences errors, and a key with a "/" uses slashes as
// the separator (so dots inside it are literal, as in a VLAN interface name).
// It returns the separator-split segments.
func sysctlKey(key string) []string {
	key = strings.TrimPrefix(strings.TrimSpace(key), "-")
	if strings.Contains(key, "/") {
		return strings.Split(strings.Trim(key, "/"), "/")
	}
	return strings.Split(key, ".")
}

// sysctlFindings checks the forwarding drop-in. The profile writes only
// net.* forwarding knobs there, so the drop-in is held to the net.* tree: no
// key outside it is restored. The knobs that hand the kernel a program to run
// are named explicitly, so the refusal says why they matter.
func sysctlFindings(file, content string) []RestoreFinding {
	var out []RestoreFinding
	configLines(content, func(n int, line string) {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			return
		}
		refuse := func(reason string) {
			out = append(out, RestoreFinding{File: file, Line: n, Text: line, Reason: reason})
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			refuse("not a key = value line")
			return
		}
		segs := sysctlKey(key)
		for _, s := range segs {
			if s == "" || s == "." || s == ".." {
				refuse("malformed sysctl key")
				return
			}
		}
		dotted := strings.Join(segs, ".")
		switch {
		case sysctlProgramKeys[dotted], strings.HasPrefix(dotted, "kernel.usermodehelper."):
			refuse(dotted + " names a program the kernel runs as root")
		case segs[0] == "fs" && len(segs) > 1 && segs[1] == "binfmt_misc":
			refuse(dotted + " registers an interpreter the kernel runs for matching files")
		case segs[0] != "net":
			refuse(dotted + " is outside net.*, and the router's drop-in only carries forwarding knobs")
		}
	})
	return out
}

// --- dnsmasq -----------------------------------------------------------------

// dnsmasqExecOptions run a program (or a Lua script) as dnsmasq's user, which
// is root when dnsmasq keeps root for its scripts. No path makes them safe.
var dnsmasqExecOptions = map[string]bool{
	"dhcp-script":    true,
	"dhcp-luascript": true,
	"conf-script":    true,
}

// dnsmasqPathOptions are the options that read (or write) a file named by
// their value, each with the managed locations it may point at. A value
// outside them would make a restore pull config in from, or write state to, a
// place the artifact does not cover. An empty list means the option is never
// written by the router profile and is refused outright.
var dnsmasqPathOptions = map[string][]string{
	"conf-file":      {"/etc/dnsmasq.d"},
	"conf-dir":       {"/etc/dnsmasq.d"},
	"servers-file":   {"/etc/dnsmasq.d"},
	"addn-hosts":     {"/etc/dnsmasq.d", "/etc/hosts"},
	"hostsdir":       {"/etc/dnsmasq.d"},
	"dhcp-hostsfile": {"/etc/dnsmasq.d"},
	"dhcp-hostsdir":  {"/etc/dnsmasq.d"},
	"dhcp-optsfile":  {"/etc/dnsmasq.d"},
	"dhcp-optsdir":   {"/etc/dnsmasq.d"},
	"resolv-file":    {"/etc/resolv.conf", "/run/systemd/resolve", "/run/NetworkManager"},
	"dhcp-leasefile": {"/var/lib/misc", "/var/lib/dnsmasq"},
	"pid-file":       {"/run", "/var/run"},
	"log-facility":   {"/var/log"},
	"tftp-root":      nil,
	"dumpfile":       nil,
}

// underManaged reports whether path is one of the managed locations or inside
// one of them, after cleaning it (so a ".." cannot climb out).
func underManaged(path string, managed []string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	clean := filepath.Clean(path)
	for _, m := range managed {
		if clean == m || strings.HasPrefix(clean, m+"/") {
			return true
		}
	}
	return false
}

// dnsmasqFindings checks the dnsmasq drop-in: one option per line, the long
// option name, an optional =value. Script options are refused, and options
// that name a file must name one inside the managed locations.
func dnsmasqFindings(file, content string) []RestoreFinding {
	var out []RestoreFinding
	configLines(content, func(n int, line string) {
		if strings.HasPrefix(line, "#") {
			return
		}
		name, value, _ := strings.Cut(line, "=")
		name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "--"))
		value = strings.TrimSpace(value)
		refuse := func(reason string) {
			out = append(out, RestoreFinding{File: file, Line: n, Text: line, Reason: reason})
		}
		if dnsmasqExecOptions[name] {
			refuse(name + " runs a script for every lease event")
			return
		}
		managed, isPath := dnsmasqPathOptions[name]
		if !isPath {
			return
		}
		// log-facility also takes a syslog facility name, which is no path.
		if name == "log-facility" && !strings.Contains(value, "/") {
			return
		}
		if len(managed) == 0 {
			refuse(name + " is not something the router profile writes")
			return
		}
		// The path is the first comma-separated field (conf-dir carries
		// suffix filters after it).
		path, _, _ := strings.Cut(value, ",")
		if !underManaged(strings.TrimSpace(path), managed) {
			refuse(fmt.Sprintf("%s points outside %s", name, strings.Join(managed, ", ")))
		}
	})
	return out
}

// --- WireGuard ---------------------------------------------------------------

// wgHookKeys are the wg-quick keys whose value is a shell command wg-quick
// runs as root. PreUp and PreDown are never written by this family.
var wgHookKeys = map[string]bool{"preup": true, "postup": true, "predown": true, "postdown": true}

// wgNamePattern is the interface name wg-quick accepts for a config name.
var wgNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

// validWireguardName reports whether a restored conf name is one wg-quick
// would accept as an interface — and not one that reads as a flag on the
// `wg-quick up` argv the reload plan builds from it.
func validWireguardName(name string) bool {
	return wgNamePattern.MatchString(name) && !strings.HasPrefix(name, "-")
}

// The hook forms tui-wireguard writes, and the only ones a restore accepts.
// The two key-loading hooks are what makes a conf with no PrivateKey line come
// up (the key stays in its root-only file); the iptables lines are its
// forwarding server rules. Every variable token is matched by a strict class
// with no shell metacharacter, because wg-quick evaluates the line in bash.
const (
	wgIfRe   = `[A-Za-z0-9_.][A-Za-z0-9_.-]{0,31}`
	wgCIDRRe = `[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}`
	wgPeerRe = `[A-Za-z0-9+/]{43}=`
)

var (
	wgKeyHook = regexp.MustCompile(`^wg set %i private-key /etc/wireguard/(` + wgIfRe + `)\.key$`)
	wgPSKHook = regexp.MustCompile(`^wg set %i peer ` + wgPeerRe +
		` preshared-key /etc/wireguard/(` + wgIfRe + `)-[A-Za-z0-9]{1,8}\.psk$`)
	wgFwdOut = regexp.MustCompile(`^iptables -([ID]) FORWARD -i %i -o ` + wgIfRe +
		`(?: -d (` + wgCIDRRe + `))? -j ACCEPT$`)
	wgFwdBack = regexp.MustCompile(`^iptables -([ID]) FORWARD -i ` + wgIfRe +
		` -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT$`)
	wgNAT = regexp.MustCompile(`^iptables -t nat -([ID]) POSTROUTING -s (` + wgCIDRRe + `) -o ` +
		wgIfRe + `(?: -d (` + wgCIDRRe + `))? -j MASQUERADE$`)
)

// validIPv4Prefixes reports whether every non-empty capture is an IPv4 prefix.
func validIPv4Prefixes(values ...string) bool {
	for _, v := range values {
		if v == "" {
			continue
		}
		p, err := netip.ParsePrefix(v)
		if err != nil || !p.Addr().Is4() {
			return false
		}
	}
	return true
}

// acceptedWireguardHook reports whether a hook is one of the exact forms the
// family writes, for this interface and this hook key: the key-loading hooks
// and the iptables inserts in PostUp, the matching deletes in PostDown.
func acceptedWireguardHook(key, iface, value string) bool {
	verb := ""
	switch key {
	case "postup":
		if m := wgKeyHook.FindStringSubmatch(value); m != nil {
			return m[1] == iface
		}
		if m := wgPSKHook.FindStringSubmatch(value); m != nil {
			return m[1] == iface
		}
		verb = "I"
	case "postdown":
		verb = "D"
	default:
		return false
	}
	if m := wgFwdOut.FindStringSubmatch(value); m != nil {
		return m[1] == verb && validIPv4Prefixes(m[2])
	}
	if m := wgFwdBack.FindStringSubmatch(value); m != nil {
		return m[1] == verb
	}
	if m := wgNAT.FindStringSubmatch(value); m != nil {
		return m[1] == verb && validIPv4Prefixes(m[2], m[3])
	}
	return false
}

// wireguardFindings checks one wg-quick config. Its only directives that run
// anything are the four hooks; each must be one of the accepted forms.
func wireguardFindings(file, iface, content string) []RestoreFinding {
	var out []RestoreFinding
	configLines(content, func(n int, line string) {
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			return
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if !wgHookKeys[key] {
			return
		}
		if !acceptedWireguardHook(key, iface, strings.TrimSpace(value)) {
			out = append(out, RestoreFinding{File: file, Line: n, Text: line,
				Reason: "wg-quick runs this hook as root, and it is not a form tui-wireguard writes"})
		}
	})
	return out
}

// --- nftables ----------------------------------------------------------------

// nftInclude matches an nft include statement at the start of a command.
var nftInclude = regexp.MustCompile(`^include(\s|"|$)`)

// checkNftables refuses an include in a ruleset. `nft list ruleset` never
// prints one and tui-firewall never saves one, and an include is how an nft
// script would read rules from a file outside the artifact.
func checkNftables(file, content string) []RestoreFinding {
	var out []RestoreFinding
	configLines(content, func(n int, line string) {
		for _, cmd := range strings.Split(line, ";") {
			if nftInclude.MatchString(strings.TrimSpace(cmd)) {
				out = append(out, RestoreFinding{File: file, Line: n, Text: line,
					Reason: "include loads rules from a file outside the artifact"})
				return
			}
		}
	})
	return out
}

// --- accounts ----------------------------------------------------------------

// accountName is the portable user and group name shape. It also guarantees a
// name never starts with "-", so it cannot read as a flag on the useradd and
// groupadd argv it is passed on.
var accountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// checkAccounts refuses an account name useradd would not take as a plain name.
func checkAccounts(accounts []backup.Account) []RestoreFinding {
	var out []RestoreFinding
	for i, a := range accounts {
		if !accountName.MatchString(a.Name) {
			out = append(out, RestoreFinding{File: accountsLabel, Line: i + 1, Text: a.Name,
				Reason: "not a portable user name"})
		}
	}
	return out
}

// sortedStringKeys orders a map's keys, so findings come out in a stable order.
func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
