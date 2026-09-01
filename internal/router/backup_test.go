package router

import (
	"context"
	"strings"
	"testing"

	"github.com/tui-tools/tui-router/internal/backup"
)

// TestSafeRolesConfRoundTrips asserts that a well-formed roles.conf survives
// the parse-and-render a restore puts it through, keeping both the assignment
// and the knobs the profile also reads.
func TestSafeRolesConfRoundTrips(t *testing.T) {
	in := `# hand-written
WAN_IFS="eth0"
LAN_IFS="eth1 eth2"
LAN_MACS="00:00:5e:00:53:11"
LAN_ADDRESS="192.0.2.1/24"
LAN_DHCP="yes"
`
	out, err := SafeRolesConf(in)
	if err != nil {
		t.Fatalf("SafeRolesConf: %v", err)
	}
	assign := ParseRolesConf(out).Assignment
	if strings.Join(assign.WANIfs, " ") != "eth0" {
		t.Errorf("WAN set = %v, want [eth0]", assign.WANIfs)
	}
	if strings.Join(assign.LANIfs, " ") != "eth1 eth2" {
		t.Errorf("LAN set = %v, want [eth1 eth2]", assign.LANIfs)
	}
	for _, keep := range []string{`LAN_ADDRESS="192.0.2.1/24"`, `LAN_DHCP="yes"`} {
		if !strings.Contains(out, keep) {
			t.Errorf("the render dropped %q:\n%s", keep, out)
		}
	}
	// Rendering is canonical: a second pass changes nothing.
	again, err := SafeRolesConf(out)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if again != out {
		t.Errorf("the render is not stable:\n%s\n---\n%s", out, again)
	}
}

// TestSafeRolesConfRefusesInjection is the guard that matters: roles.conf is
// sourced by bash, and an artifact comes from another machine. Nothing that
// could run a command may survive into the file a restore writes.
func TestSafeRolesConfRefusesInjection(t *testing.T) {
	hostile := []string{
		"WAN_IFS=\"eth0; rm -rf /\"\n",
		"WAN_IFS=\"$(id)\"\nLAN_IFS=\"eth1\"\n",
		"WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1\"\nEXTRA=\"$(curl evil)\"\n",
		"WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1\"\nEXTRA=\"a`id`\"\n",
	}
	for _, text := range hostile {
		out, err := SafeRolesConf(text)
		if err == nil {
			t.Errorf("SafeRolesConf accepted %q and rendered:\n%s", text, out)
		}
	}
}

// TestMissingRoleDevices asserts the hardware-mismatch check: an artifact that
// assigns roles to ports this machine does not have is reported, and one whose
// names all resolve is silent.
func TestMissingRoleDevices(t *testing.T) {
	conf := "WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1 eth9\"\n"
	missing := MissingRoleDevices(conf, []string{"eth0", "eth1"})
	if strings.Join(missing, ",") != "eth9" {
		t.Errorf("missing = %v, want [eth9]", missing)
	}
	if got := MissingRoleDevices(conf, []string{"eth0", "eth1", "eth9"}); len(got) != 0 {
		t.Errorf("a matching machine reported %v", got)
	}
	// A MAC-pinned assignment is not name-checked: the MAC is exactly how an
	// operator says "whatever this port is called now".
	byMAC := "WAN_MACS=\"00:00:5e:00:53:10\"\nLAN_IFS=\"eth1\"\n"
	if got := MissingRoleDevices(byMAC, []string{"eth1"}); len(got) != 0 {
		t.Errorf("MAC-pinned assignment reported %v", got)
	}
}

// TestParseLinkNames reads the shape `ip -j link` produces and drops the
// loopback, which never carries a role.
func TestParseLinkNames(t *testing.T) {
	const linkJSON = `[{"ifname":"lo"},{"ifname":"eth0"},{"ifname":"eth1"}]`
	got := ParseLinkNames(linkJSON)
	if strings.Join(got, ",") != "eth0,eth1" {
		t.Errorf("names = %v, want [eth0 eth1]", got)
	}
	if got := ParseLinkNames("not json"); got != nil {
		t.Errorf("a payload that will not parse yielded %v, want nil", got)
	}
}

// TestDemoCollectsTheSupportingFiles asserts the demo backend exports the four
// files stage 1.1 added, so --demo exercises the whole artifact.
func TestDemoCollectsTheSupportingFiles(t *testing.T) {
	src, err := NewFake().CollectSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"roles":          src.Roles,
		"sysctl":         src.Sysctl,
		"resolved":       src.Resolved,
		"firewall rules": src.FirewallRules,
	} {
		if strings.TrimSpace(content) == "" {
			t.Errorf("the demo export carries no %s", name)
		}
	}
}

// TestDemoReloadPlanMirrorsTheArtifact asserts the demo previews a reload step
// for each config subsystem the artifact carries and none for the ones it does
// not — the parity the real plan promises.
func TestDemoReloadPlanMirrorsTheArtifact(t *testing.T) {
	fake := NewFake()
	src, err := fake.CollectSources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var previews []string
	for _, step := range fake.ReloadPlan(src) {
		previews = append(previews, step.String())
	}
	joined := strings.Join(previews, "\n")
	for _, want := range []string{
		"networkctl reload",
		"systemctl restart systemd-resolved",
		"systemctl restart dnsmasq",
		"sysctl --system",
		"wg-quick down wg0",
		"wg-quick up wg0",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the demo reload plan is missing %q:\n%s", want, joined)
		}
	}

	// An artifact with only a ruleset needs no reload at all: the ruleset goes
	// through the atomic apply, not through this plan.
	if steps := fake.ReloadPlan(backup.Sources{Nftables: "table inet filter {}"}); len(steps) != 0 {
		t.Errorf("a ruleset-only artifact previewed %d reload step(s)", len(steps))
	}
}

// TestFakeWriteConfigGuardsRoles asserts the demo's write goes through the
// same validator the real one does, so --demo proves the guard rather than
// only asserting it exists.
func TestFakeWriteConfigGuardsRoles(t *testing.T) {
	fake := NewEmptyFake()
	err := fake.WriteConfig(context.Background(), backup.SubsystemRoles, "",
		"WAN_IFS=\"eth0 $(id)\"\nLAN_IFS=\"eth1\"\n")
	if err == nil {
		t.Fatal("the demo wrote a roles.conf carrying a command substitution")
	}
}
