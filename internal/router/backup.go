package router

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/tui-tools/tui-router/internal/backup"
)

// BackupBackend is the boundary export and restore go through. Like the
// read-only Backend, it keeps every process start inside this package (the
// family's single exec site): the command layer orchestrates the preview,
// the confirmation and the keep-timer, and calls these methods to touch the
// machine. Both the real router and the in-memory demo implement it, so the
// whole export→restore loop runs with no root and no real router.
type BackupBackend interface {
	// Hostname names the machine an export was taken from. It is read here so
	// the pure backup package never has to.
	Hostname() string
	// CollectSources reads every subsystem read-only and returns the router's
	// logical identity, already scrubbed of secrets (WireGuard key material is
	// stripped and referenced by path).
	CollectSources(ctx context.Context) (backup.Sources, error)
	// NftablesSnapshot returns the live ruleset, captured before a restore so
	// the connectivity-safe rollback has something to replay.
	NftablesSnapshot(ctx context.Context) (string, error)
	// ApplyNftables runs one `nft -f -` transaction with the given payload
	// (a flush-and-replay script). It is all-or-nothing: nft applies the whole
	// script or none of it.
	ApplyNftables(ctx context.Context, payload string) error
	// WriteConfig installs one config-file part. subsystem is one of the
	// backup subsystem tags; name is the base filename for the multi-file
	// subsystems (networkd, wireguard) and empty for the single-file ones.
	WriteConfig(ctx context.Context, subsystem, name, content string) error
	// ApplyAccounts provisions the router's own users/groups by name and role.
	// Stage 1 carries no credential hashes, so this only ensures the accounts
	// exist; secrets are set out of band.
	ApplyAccounts(ctx context.Context, accounts []backup.Account) error
	// ReloadPlan is the ordered list of commands that make the config files a
	// restore just wrote take effect. It is built from the artifact, so a
	// restore that carried no dnsmasq config never previews a dnsmasq restart.
	ReloadPlan(target backup.Sources) []ReloadStep
	// RunReload executes one step of that plan — exactly the argv the step
	// previewed, so the confirm's promise holds.
	RunReload(ctx context.Context, step ReloadStep) error
	// LinkNames reports the interface names this machine currently has, so a
	// restore can warn when the artifact's roles.conf names devices that are
	// not here. An error means the list is unknown, and the caller warns about
	// that rather than pretending the names matched.
	LinkNames(ctx context.Context) ([]string, error)
}

// ReloadStep is one previewed reload command. Argv is what runs and Preview is
// what the operator was shown; the backend renders the preview from the argv,
// so the two cannot drift.
type ReloadStep struct {
	// Argv is the literal command, escalation prefix excluded.
	Argv []string
	// Preview is the command line as the confirm dialog shows it, escalation
	// prefix included.
	Preview string
	// Description says, in one line, why this step is in the plan.
	Description string
	// Destructive marks a step that can drop the operator's own session — the
	// networkd reload and the WireGuard bounce both can.
	Destructive bool
}

// String renders a step for a plain-text preview block.
func (s ReloadStep) String() string {
	if s.Preview != "" {
		return s.Preview
	}
	return strings.Join(s.Argv, " ")
}

// SafeRolesConf re-parses a roles.conf that came out of an artifact and
// re-renders it through the profile's own validator. roles.conf is sourced by
// bash, and an artifact is bytes from another machine: rendering the parsed
// assignment back out is what guarantees a restore can only ever write
// interface names and MACs into it, never a command substitution someone
// planted in the file before it was exported.
//
// The unrecognised lines (LAN_ADDRESS, LAN_DHCP, anything an operator added)
// are carried through, so a restore does not quietly drop the knobs the
// profile also reads — but they are validated as plain assignments first.
func SafeRolesConf(text string) (string, error) {
	conf := ParseRolesConf(text)
	safe := RolesConf{Assignment: conf.Assignment}
	for _, extra := range conf.Extras {
		if !safeRolesExtra(extra) {
			return "", fmt.Errorf("roles.conf carries a line a restore will not write back: %q", extra)
		}
		safe.Extras = append(safe.Extras, extra)
	}
	return RenderRolesConf(safe)
}

// safeRolesExtra reports whether an unrecognised roles.conf line is a plain
// KEY="value" assignment with no shell metacharacter in the value. Anything
// else — a substitution, a pipe, a second statement — is refused rather than
// written back into a file bash sources.
func safeRolesExtra(line string) bool {
	m := rolesLine.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	value := unquote(m[2])
	return !strings.ContainsAny(value, "$`\\\"'();|&<>\n") && !strings.Contains(value, "#")
}

// MissingRoleDevices reports the interface names an artifact's roles.conf
// assigns that this machine does not have. A restore onto hardware whose NICs
// are named differently would leave the router assigning roles to ports that
// do not exist — silently unrouted — so the caller warns and asks again.
//
// MAC-pinned members are deliberately not checked here: a MAC that is absent
// is the same class of problem, but it is reported by the profile's own
// resolver, and a MAC list is how an operator says "whatever this port is
// called now". Names are what break on new hardware.
func MissingRoleDevices(rolesText string, present []string) []string {
	assigned := ParseRolesConf(rolesText).Assignment
	have := map[string]bool{}
	for _, name := range present {
		have[name] = true
	}
	seen := map[string]bool{}
	var missing []string
	for _, name := range append(append([]string{}, assigned.WANIfs...), assigned.LANIfs...) {
		if name == "" || have[name] || seen[name] {
			continue
		}
		seen[name] = true
		missing = append(missing, name)
	}
	sort.Strings(missing)
	return missing
}
