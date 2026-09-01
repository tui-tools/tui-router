package router

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// This file is the pure half of the roles wizard: parsing and rendering
// /etc/omarchy/router/roles.conf, validating what goes into it, diffing the
// change, and building the anti-lockout revert commands. Nothing here touches
// the machine — the exec half lives in roles_real.go, behind the same
// preview-then-confirm contract as every other mutation in the family.

// Where the router profile keeps the role assignment. The file is sourced by
// bash (omarchy-router-nics, network-router.sh), which is why everything
// rendered into it is validated against strict shapes below.
const (
	// RolesDir is the router profile's configuration directory; its presence
	// is how the cockpit knows this machine runs the router profile.
	RolesDir = "/etc/omarchy/router"
	// RolesConfPath is the role assignment file itself.
	RolesConfPath = RolesDir + "/roles.conf"
	// RolesPrevPath is where the wizard stages the previous assignment so the
	// scheduled revert can restore it.
	RolesPrevPath = RolesConfPath + ".prev"
	// RevertUnit is the transient systemd unit the anti-lockout revert runs
	// as; cancelling the revert stops this unit's timer.
	RevertUnit = "tui-router-roles-revert"
	// RevertDelay is how long the operator has to confirm connectivity after
	// an apply before the revert restores the previous assignment.
	RevertDelay = 120 * time.Second
)

// RoleAssignment is the many-to-many role mapping roles.conf carries: each
// role is a set, an interface may be listed by name or pinned by MAC, and the
// same physical port may back both sets (a one-armed router is legal).
type RoleAssignment struct {
	WANIfs  []string `json:"wanIfs"`
	WANMacs []string `json:"wanMacs"`
	LANIfs  []string `json:"lanIfs"`
	LANMacs []string `json:"lanMacs"`
}

// Assigned reports whether both roles have at least one member. Until both
// are assigned the router profile forwards nothing (safe mode), which is the
// state the wizard exists to move the machine out of.
func (a RoleAssignment) Assigned() bool {
	return (len(a.WANIfs)+len(a.WANMacs)) > 0 && (len(a.LANIfs)+len(a.LANMacs)) > 0
}

// RolesConf is one parsed roles.conf: the assignment, plus every line the
// parser did not recognise, kept verbatim so a render never drops the
// LAN_ADDRESS/LAN_DHCP knobs (or anything an operator added by hand).
type RolesConf struct {
	Assignment RoleAssignment `json:"assignment"`
	// Extras are the unrecognised KEY=VALUE lines, in file order, exactly as
	// they were read. RenderRolesConf writes them back after the roles.
	Extras []string `json:"extras,omitempty"`
}

// RolesStatus is what the cockpit knows about the role assignment: whether
// this machine runs the router profile at all, whether roles.conf exists, its
// content, and the parsed assignment.
type RolesStatus struct {
	// ProfilePresent reports that /etc/omarchy/router/ exists, i.e. this is a
	// router-profile host where the wizard applies.
	ProfilePresent bool `json:"profilePresent"`
	// ConfPresent reports that roles.conf itself exists.
	ConfPresent bool `json:"confPresent"`
	// Content is the file as read, empty when absent or unreadable.
	Content string `json:"-"`
	// Parsed is the assignment read from Content.
	Parsed RolesConf `json:"parsed"`
}

// NeedsWizard reports the gap the wizard fills: a router-profile host whose
// roles are not both assigned — either roles.conf says so, or the file the
// profile should have written is missing entirely.
func (s RolesStatus) NeedsWizard() bool {
	return s.ProfilePresent && !s.Parsed.Assignment.Assigned()
}

// rolesLine matches one shell variable assignment in roles.conf.
var rolesLine = regexp.MustCompile(`^([A-Z][A-Z0-9_]*)=(.*)$`)

// ParseRolesConf reads a roles.conf. It is a read-only, tolerant parse of a
// file bash will source: comments and blanks are skipped, the four role sets
// (and their singular WAN_IF/LAN_IF forms) are collected, and every other
// assignment line is preserved verbatim in Extras. A line the parser cannot
// read is kept as an extra rather than lost — parsing never destroys.
func ParseRolesConf(text string) RolesConf {
	var conf RolesConf
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := rolesLine.FindStringSubmatch(line)
		if m == nil {
			conf.Extras = append(conf.Extras, line)
			continue
		}
		key, value := m[1], unquote(m[2])
		fields := strings.Fields(value)
		switch key {
		case "WAN_IFS", "WAN_IF":
			conf.Assignment.WANIfs = append(conf.Assignment.WANIfs, fields...)
		case "WAN_MACS", "WAN_MAC":
			conf.Assignment.WANMacs = append(conf.Assignment.WANMacs, lowerAll(fields)...)
		case "LAN_IFS", "LAN_IF":
			conf.Assignment.LANIfs = append(conf.Assignment.LANIfs, fields...)
		case "LAN_MACS", "LAN_MAC":
			conf.Assignment.LANMacs = append(conf.Assignment.LANMacs, lowerAll(fields)...)
		default:
			conf.Extras = append(conf.Extras, line)
		}
	}
	return conf
}

// unquote strips one pair of surrounding quotes, the way the file writes its
// values. Inner quotes are left alone; the validators refuse them anyway.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// lowerAll lower-cases a MAC list, the canonical form the resolver compares.
func lowerAll(fields []string) []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, strings.ToLower(f))
	}
	return out
}

// ifaceName is the shape of a kernel interface name: up to 15 characters,
// starting with an alphanumeric, then alphanumerics, dot, dash, underscore.
// roles.conf is sourced by bash, so anything outside this shape — quotes,
// spaces, $(), backticks — must never be rendered into it.
var ifaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// macAddr is a six-octet colon-separated MAC, lower-case.
var macAddr = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)

// ValidIfaceName reports whether a string is safe to render as an interface
// name in roles.conf.
func ValidIfaceName(name string) bool { return ifaceName.MatchString(name) }

// ValidMAC reports whether a string is a well-formed lower-case MAC.
func ValidMAC(mac string) bool { return macAddr.MatchString(mac) }

// Validate refuses any member that could not be a real interface name or MAC.
// This is the injection guard: the file is sourced by bash, and the only
// content the wizard ever writes into a value is what passes here.
func (a RoleAssignment) Validate() error {
	for _, name := range append(append([]string{}, a.WANIfs...), a.LANIfs...) {
		if !ValidIfaceName(name) {
			return fmt.Errorf("%q is not a valid interface name", name)
		}
	}
	for _, mac := range append(append([]string{}, a.WANMacs...), a.LANMacs...) {
		if !ValidMAC(mac) {
			return fmt.Errorf("%q is not a valid MAC address", mac)
		}
	}
	return nil
}

// rolesHeader is the comment RenderRolesConf writes above the assignment, so
// an operator editing the file by hand later knows what they are looking at.
const rolesHeader = `# Omarchy Router: which interfaces play which role. Each role is a SET -- list
# more than one for several uplinks or several LAN ports. Assign by name
# (WAN_IFS/LAN_IFS) or by MAC (WAN_MACS/LAN_MACS -- survives a name change).
# Re-apply after editing: omarchy-router-nics --apply
# Written by tui-router's roles wizard.`

// RenderRolesConf writes a roles.conf from an assignment, carrying the extras
// through unchanged. It refuses an assignment that fails Validate, so nothing
// that could confuse the shell that sources the file is ever rendered.
func RenderRolesConf(conf RolesConf) (string, error) {
	if err := conf.Assignment.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(rolesHeader + "\n")
	fmt.Fprintf(&b, "WAN_IFS=%q\n", strings.Join(conf.Assignment.WANIfs, " "))
	fmt.Fprintf(&b, "WAN_MACS=%q\n", strings.Join(conf.Assignment.WANMacs, " "))
	fmt.Fprintf(&b, "LAN_IFS=%q\n", strings.Join(conf.Assignment.LANIfs, " "))
	fmt.Fprintf(&b, "LAN_MACS=%q\n", strings.Join(conf.Assignment.LANMacs, " "))
	for _, extra := range conf.Extras {
		b.WriteString(extra + "\n")
	}
	return b.String(), nil
}

// revertShellCommand is the exact shell line the scheduled revert runs. It is
// a compile-time constant — no operator input is ever interpolated into it —
// which is what makes handing it to `sh -c` safe.
const revertShellCommand = "cp " + RolesPrevPath + " " + RolesConfPath +
	" && omarchy-router-nics --apply"

// RevertScheduleArgv builds the systemd-run invocation that arms the
// anti-lockout revert: after delay, restore the previous roles.conf and
// re-apply it. The argv is fully constant apart from the delay, and the delay
// is rendered as a whole number of seconds.
func RevertScheduleArgv(delay time.Duration) []string {
	seconds := int(delay.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return []string{
		"systemd-run",
		"--on-active=" + strconv.Itoa(seconds),
		"--unit=" + RevertUnit,
		"sh", "-c", revertShellCommand,
	}
}

// CancelRevertArgv builds the command that disarms the revert once the
// operator has confirmed connectivity: stop both the timer and the service,
// so the revert neither fires later nor keeps running now.
func CancelRevertArgv() []string {
	return []string{"systemctl", "stop", RevertUnit + ".timer", RevertUnit + ".service"}
}

// ManualRevertInstructions is what the wizard prints when systemd-run is not
// available to arm an automatic revert: the operator gets the exact commands
// to run by hand if the new assignment cuts them off.
func ManualRevertInstructions() []string {
	return []string{
		"systemd-run is not available, so no automatic revert was scheduled.",
		"If this apply cuts you off, restore the previous assignment from console:",
		"  cp " + RolesPrevPath + " " + RolesConfPath,
		"  omarchy-router-nics --apply",
	}
}

// UnifiedDiff renders a small unified diff between two texts, used to preview
// the roles.conf change. It is a plain LCS line diff with full context — the
// files it compares are a dozen lines, and the point is that the operator
// reads every changed line before confirming.
func UnifiedDiff(name, oldText, newText string) string {
	oldLines := splitLines(oldText)
	newLines := splitLines(newText)

	// Longest-common-subsequence table, small inputs only.
	n, m := len(oldLines), len(newLines)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if oldLines[i] == newLines[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "--- %s (current)\n+++ %s (new)\n", name, name)
	fmt.Fprintf(&b, "@@ -1,%d +1,%d @@\n", n, m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case oldLines[i] == newLines[j]:
			b.WriteString(" " + oldLines[i] + "\n")
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			b.WriteString("-" + oldLines[i] + "\n")
			i++
		default:
			b.WriteString("+" + newLines[j] + "\n")
			j++
		}
	}
	for ; i < n; i++ {
		b.WriteString("-" + oldLines[i] + "\n")
	}
	for ; j < m; j++ {
		b.WriteString("+" + newLines[j] + "\n")
	}
	return b.String()
}

// splitLines splits a text into lines without a trailing empty element.
func splitLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// WritePlan is the previewed roles.conf write: the exact command the confirm
// dialog shows, staged so what runs is what was shown.
type WritePlan struct {
	// Preview is the literal command line that will install roles.conf.
	Preview string
}

// ApplyPlan is the previewed apply-with-revert: every command the second
// confirm covers, plus how the revert degrades when systemd-run is absent.
type ApplyPlan struct {
	// StagePreview installs the previous assignment as roles.conf.prev.
	StagePreview string
	// SchedulePreview arms the timed revert; empty when systemd-run is absent.
	SchedulePreview string
	// ApplyPreview re-runs the profile's network script for the new mapping.
	ApplyPreview string
	// CancelPreview disarms the revert after connectivity is confirmed.
	CancelPreview string
	// HasSystemdRun reports whether the automatic revert can be armed.
	HasSystemdRun bool
	// ManualRevert is the fallback instruction block when it cannot.
	ManualRevert []string
}

// ApplyResult is what the apply step reports back to the wizard.
type ApplyResult struct {
	// Output is the apply command's output.
	Output string
	// RevertScheduled reports whether the timed revert is armed.
	RevertScheduled bool
}

// RoleManager is the mutation surface the roles wizard drives. The cockpit's
// Backend stays read-only; a backend that can also manage roles implements
// this alongside it, and the UI reaches it by type assertion — so the base
// contract ("Read changes nothing") is untouched.
type RoleManager interface {
	// NicsPreview runs `omarchy-router-nics --preview`, a read-only render of
	// the role→device mapping the profile would apply.
	NicsPreview(ctx context.Context) (string, error)
	// WritePlan previews the roles.conf install for the given content.
	WritePlan(content string) WritePlan
	// WriteRoles stages the content into a temp file and installs it as
	// roles.conf — exactly the command WritePlan previewed.
	WriteRoles(ctx context.Context, content string) error
	// ApplyPlan previews the whole apply-with-revert sequence.
	ApplyPlan() ApplyPlan
	// ApplyRoles stages prevContent as roles.conf.prev, arms the timed revert
	// (when systemd-run exists) and runs `omarchy-router-nics --apply`.
	ApplyRoles(ctx context.Context, prevContent string) (ApplyResult, error)
	// CancelRevert disarms the timed revert after connectivity is confirmed.
	CancelRevert(ctx context.Context) error
}

// PowerManager is the power surface behind the cockpit's reboot/poweroff
// keys, implemented alongside Backend the same way RoleManager is.
type PowerManager interface {
	// RebootPreview is the exact command the reboot confirm shows.
	RebootPreview() string
	// Reboot runs it.
	Reboot(ctx context.Context) error
	// PoweroffPreview is the exact command the poweroff confirm shows.
	PoweroffPreview() string
	// Poweroff runs it.
	Poweroff(ctx context.Context) error
}
