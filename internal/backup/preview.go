package backup

import (
	"fmt"
	"sort"
	"strings"
)

// ChangeKind is what a restore would do to one subsystem item.
type ChangeKind string

const (
	// ChangeUnchanged: the artifact matches the machine; nothing to apply.
	ChangeUnchanged ChangeKind = "unchanged"
	// ChangeReplace: the item exists on both sides but differs.
	ChangeReplace ChangeKind = "replace"
	// ChangeAdd: the artifact has an item the machine does not.
	ChangeAdd ChangeKind = "add"
	// ChangeRemove: the machine has an item the artifact does not. Stage 1
	// reports these but leaves them in place — a restore adds and replaces,
	// it does not prune — so the operator sees what the artifact omits.
	ChangeRemove ChangeKind = "remove"
)

// Change is one line of the restore preview: which subsystem, which item, what
// would happen, and a short human summary.
type Change struct {
	Subsystem string
	Item      string
	Kind      ChangeKind
	Summary   string
}

// Preview is the whole restore preview: every change the operator sees before
// the single confirmation. It is derived purely from the current and target
// Sources, so --dry-run and the real run compute exactly the same thing.
type Preview struct {
	Changes []Change
}

// Diff computes the preview between the machine's current Sources and the
// artifact's target Sources.
func Diff(current, target Sources) Preview {
	var p Preview
	// Roles first: it is the file that says what the machine is for, and the
	// operator should read that line before the ones that implement it.
	p.add(SubsystemRoles, "roles.conf", current.Roles, target.Roles)
	p.add(SubsystemNftables, "ruleset", current.Nftables, target.Nftables)
	p.add(SubsystemDHCPDNS, "config", current.DHCPDNS, target.DHCPDNS)
	p.add(SubsystemSysctl, "forwarding", current.Sysctl, target.Sysctl)
	p.add(SubsystemResolved, "drop-in", current.Resolved, target.Resolved)
	p.add(SubsystemFirewallRules, "saved ruleset", current.FirewallRules, target.FirewallRules)
	p.addMap(SubsystemNetworkd, current.Networkd, target.Networkd)
	p.addWG(current.Wireguard, target.Wireguard)
	p.addAccounts(current.Accounts, target.Accounts)
	return p
}

// HasChanges reports whether the restore would write anything.
func (p Preview) HasChanges() bool {
	for _, c := range p.Changes {
		if c.Kind != ChangeUnchanged {
			return true
		}
	}
	return false
}

// String renders the preview as the block the confirm step shows.
func (p Preview) String() string {
	if len(p.Changes) == 0 {
		return "  (the artifact carries nothing for any subsystem)"
	}
	var b strings.Builder
	for _, c := range p.Changes {
		item := c.Subsystem
		if c.Item != "" {
			item += "/" + c.Item
		}
		fmt.Fprintf(&b, "  %-9s %-24s %s\n", c.Kind, item, c.Summary)
	}
	return strings.TrimRight(b.String(), "\n")
}

// add records a change for a single-file subsystem.
func (p *Preview) add(subsystem, item, current, target string) {
	if strings.TrimSpace(target) == "" {
		// The artifact carries nothing for this subsystem: leave the machine's
		// own state untouched and say so only if the machine had something.
		return
	}
	kind := ChangeAdd
	if strings.TrimSpace(current) != "" {
		kind = ChangeReplace
		if normalize(current) == normalize(target) {
			kind = ChangeUnchanged
		}
	}
	p.Changes = append(p.Changes, Change{
		Subsystem: subsystem, Item: item, Kind: kind,
		Summary: lineDelta(current, target),
	})
}

// addMap records changes for a filename-keyed subsystem (networkd units).
func (p *Preview) addMap(subsystem string, current, target map[string]string) {
	for _, name := range union(keys(current), keys(target)) {
		cur, hasCur := current[name]
		tgt, hasTgt := target[name]
		switch {
		case hasTgt && !hasCur:
			p.Changes = append(p.Changes, Change{subsystem, name, ChangeAdd,
				fmt.Sprintf("%d lines", countLines(tgt))})
		case hasTgt && hasCur:
			kind := ChangeReplace
			if normalize(cur) == normalize(tgt) {
				kind = ChangeUnchanged
			}
			p.Changes = append(p.Changes, Change{subsystem, name, kind, lineDelta(cur, tgt)})
		case !hasTgt && hasCur:
			p.Changes = append(p.Changes, Change{subsystem, name, ChangeRemove,
				"present on the machine, absent from the artifact"})
		}
	}
}

// addWG records changes for the WireGuard interfaces.
func (p *Preview) addWG(current, target map[string]WGConf) {
	cur := map[string]string{}
	for k, v := range current {
		cur[k] = v.Config
	}
	tgt := map[string]string{}
	for k, v := range target {
		tgt[k] = v.Config
	}
	p.addMap(SubsystemWireguard, cur, tgt)
}

// addAccounts records the accounts change as one line naming the counts.
func (p *Preview) addAccounts(current, target []Account) {
	if len(target) == 0 {
		return
	}
	kind := ChangeReplace
	if accountsEqual(current, target) {
		kind = ChangeUnchanged
	} else if len(current) == 0 {
		kind = ChangeAdd
	}
	p.Changes = append(p.Changes, Change{
		Subsystem: SubsystemAccounts, Item: "", Kind: kind,
		Summary: fmt.Sprintf("%d account(s), names and roles only", len(target)),
	})
}

// lineDelta summarizes two texts as their line counts, the cheapest honest diff
// a preview can show without inventing a semantic one.
func lineDelta(current, target string) string {
	if strings.TrimSpace(current) == "" {
		return fmt.Sprintf("%d lines (new)", countLines(target))
	}
	return fmt.Sprintf("%d → %d lines", countLines(current), countLines(target))
}

// countLines counts the non-empty lines of a text.
func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

// normalize compares two texts ignoring trailing whitespace differences.
func normalize(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed == "" {
			continue
		}
		b.WriteString(trimmed)
		b.WriteByte('\n')
	}
	return b.String()
}

// accountsEqual reports whether two account lists describe the same set.
func accountsEqual(a, b []Account) bool {
	if len(a) != len(b) {
		return false
	}
	sa := append([]Account(nil), a...)
	sb := append([]Account(nil), b...)
	sort.Slice(sa, func(i, j int) bool { return sa[i].Name < sa[j].Name })
	sort.Slice(sb, func(i, j int) bool { return sb[i].Name < sb[j].Name })
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}

// keys returns the sorted keys of a string map.
func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// union merges two sorted key lists into one sorted, de-duplicated list.
func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string(nil), a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
