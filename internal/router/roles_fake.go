package router

import (
	"context"
	"strings"
)

// This file is the demo's side of the roles wizard and the power keys. The
// fake mirrors the real backend method for method, so --demo walks the whole
// wizard — banner, selection, both previews, both confirms, the revert cancel
// — while running nothing and touching nothing.

// fakeRoles is the demo's role state: the roles.conf content the demo router
// pretends to have, and what the wizard has "done" to it so far.
type fakeRoles struct {
	content         string
	applied         bool
	revertScheduled bool
	revertCancelled bool
	// ran records the previews of every command the demo pretended to run,
	// so a test can assert the demo's parity with the real sequence.
	ran []string
}

// demoRolesConf is the demo router's starting roles.conf: present, sourced by
// the profile, and unassigned — the safe-mode state the wizard exists for.
const demoRolesConf = `# Omarchy Router: which interfaces play which role.
WAN_IFS=""
WAN_MACS=""
LAN_IFS=""
LAN_MACS=""
LAN_ADDRESS="192.0.2.1/24"
LAN_DHCP="yes"
`

// readRoles reports the demo's role state, mirroring Real.readRoles.
func (f *Fake) readRoles() RolesStatus {
	content := f.roles.content
	return RolesStatus{
		ProfilePresent: true,
		ConfPresent:    true,
		Content:        content,
		Parsed:         ParseRolesConf(content),
	}
}

// NicsPreview renders the mapping the way omarchy-router-nics --preview does,
// resolved from the demo's own roles.conf and interfaces.
func (f *Fake) NicsPreview(_ context.Context) (string, error) {
	conf := ParseRolesConf(f.roles.content)
	lines := []string{
		"WAN  " + orUnassigned(append(conf.Assignment.WANIfs, f.resolveMacs(conf.Assignment.WANMacs)...)),
		"LAN  " + orUnassigned(append(conf.Assignment.LANIfs, f.resolveMacs(conf.Assignment.LANMacs)...)),
		"",
		"Preview only. Re-run with --apply to write the .network units and reload.",
	}
	return strings.Join(lines, "\n"), nil
}

// resolveMacs maps demo MACs back to demo interface names, the way the real
// script resolves a MAC to the device that carries it now.
func (f *Fake) resolveMacs(macs []string) []string {
	byMAC := map[string]string{}
	for _, iface := range demoInterfaces() {
		byMAC[iface.MAC] = iface.Name
	}
	var out []string
	for _, mac := range macs {
		if name, ok := byMAC[mac]; ok {
			out = append(out, name)
		}
	}
	return out
}

// orUnassigned renders a role's device set the way the script does.
func orUnassigned(devs []string) string {
	if len(devs) == 0 {
		return "unassigned"
	}
	return strings.Join(devs, " ")
}

// WritePlan previews the demo's roles.conf install.
func (f *Fake) WritePlan(string) WritePlan {
	return WritePlan{
		Preview: "install -m 644 <staged roles.conf> " + RolesConfPath + " (demo: not run)",
	}
}

// WriteRoles records the new content; nothing is written anywhere.
func (f *Fake) WriteRoles(_ context.Context, content string) error {
	f.roles.ran = append(f.roles.ran, "install roles.conf")
	f.roles.content = content
	return nil
}

// ApplyPlan previews the demo's apply-with-revert sequence, systemd-run
// included, so the demo walks the same three-command confirm the real
// backend shows.
func (f *Fake) ApplyPlan() ApplyPlan {
	return ApplyPlan{
		StagePreview:    "install -m 644 <staged previous roles.conf> " + RolesPrevPath + " (demo: not run)",
		SchedulePreview: strings.Join(RevertScheduleArgv(RevertDelay), " ") + " (demo: not run)",
		ApplyPreview:    "omarchy-router-nics --apply (demo: not run)",
		CancelPreview:   strings.Join(CancelRevertArgv(), " ") + " (demo: not run)",
		HasSystemdRun:   true,
	}
}

// ApplyRoles pretends to apply and arms the pretend revert.
func (f *Fake) ApplyRoles(_ context.Context, _ string) (ApplyResult, error) {
	f.roles.ran = append(f.roles.ran,
		"install roles.conf.prev", "systemd-run revert", "omarchy-router-nics --apply")
	f.roles.applied = true
	f.roles.revertScheduled = true
	return ApplyResult{
		// The demo's output is the command talking, not the verdict: the
		// wizard states the outcome itself and shows this under a heading.
		Output:          "(demo: omarchy-router-nics was not run)",
		RevertScheduled: true,
	}, nil
}

// CancelRevert pretends to disarm the revert.
func (f *Fake) CancelRevert(_ context.Context) error {
	f.roles.ran = append(f.roles.ran, "systemctl stop revert")
	f.roles.revertScheduled = false
	f.roles.revertCancelled = true
	return nil
}

// RebootPreview is the demo's reboot preview; Reboot records and does nothing.
func (f *Fake) RebootPreview() string { return "systemctl reboot (demo: not run)" }

// Reboot pretends.
func (f *Fake) Reboot(_ context.Context) error {
	f.roles.ran = append(f.roles.ran, "systemctl reboot")
	return nil
}

// PoweroffPreview is the demo's poweroff preview; Poweroff records only.
func (f *Fake) PoweroffPreview() string { return "systemctl poweroff (demo: not run)" }

// Poweroff pretends.
func (f *Fake) Poweroff(_ context.Context) error {
	f.roles.ran = append(f.roles.ran, "systemctl poweroff")
	return nil
}
