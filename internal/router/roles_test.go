package router

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The backends must offer the wizard and the power keys the same surface, so
// the demo walks exactly the flow the real machine gets.
var (
	_ RoleManager  = (*Real)(nil)
	_ RoleManager  = (*Fake)(nil)
	_ PowerManager = (*Real)(nil)
	_ PowerManager = (*Fake)(nil)
)

func TestRolesConfRoundTrip(t *testing.T) {
	conf := RolesConf{
		Assignment: RoleAssignment{
			WANIfs:  []string{"enp1s0"},
			WANMacs: []string{"00:00:5e:00:53:10"},
			LANIfs:  []string{"enp2s0", "enp3s0"},
			LANMacs: []string{"00:00:5e:00:53:11"},
		},
		Extras: []string{`LAN_ADDRESS="192.0.2.1/24"`, `LAN_DHCP="yes"`},
	}
	text, err := RenderRolesConf(conf)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	back := ParseRolesConf(text)
	if !reflect.DeepEqual(back, conf) {
		t.Errorf("round trip lost data:\n got %+v\nwant %+v", back, conf)
	}
}

func TestParseRolesConfIsTolerant(t *testing.T) {
	text := `# a comment
WAN_IFS=enp1s0
WAN_IF="enp5s0"
LAN_IFS='enp2s0 enp3s0'
LAN_MAC="00:00:5E:00:53:AA"

not a variable line
LAN_ADDRESS="192.0.2.1/24"
`
	conf := ParseRolesConf(text)
	if !reflect.DeepEqual(conf.Assignment.WANIfs, []string{"enp1s0", "enp5s0"}) {
		t.Errorf("WAN ifs = %v (singular WAN_IF should merge)", conf.Assignment.WANIfs)
	}
	if !reflect.DeepEqual(conf.Assignment.LANIfs, []string{"enp2s0", "enp3s0"}) {
		t.Errorf("LAN ifs = %v (single-quoted set)", conf.Assignment.LANIfs)
	}
	// MACs are canonicalised to lower case, the form the resolver compares.
	if !reflect.DeepEqual(conf.Assignment.LANMacs, []string{"00:00:5e:00:53:aa"}) {
		t.Errorf("LAN macs = %v, want lower-cased", conf.Assignment.LANMacs)
	}
	// Unrecognised lines are preserved, never dropped.
	if len(conf.Extras) != 2 ||
		conf.Extras[0] != "not a variable line" ||
		conf.Extras[1] != `LAN_ADDRESS="192.0.2.1/24"` {
		t.Errorf("extras = %v, want the two unrecognised lines kept verbatim", conf.Extras)
	}
}

func TestAssigned(t *testing.T) {
	cases := []struct {
		name string
		a    RoleAssignment
		want bool
	}{
		{"empty", RoleAssignment{}, false},
		{"wan only", RoleAssignment{WANIfs: []string{"eth0"}}, false},
		{"lan only", RoleAssignment{LANMacs: []string{"00:00:5e:00:53:01"}}, false},
		{"both by name", RoleAssignment{WANIfs: []string{"eth0"}, LANIfs: []string{"eth1"}}, true},
		{"both by mac", RoleAssignment{
			WANMacs: []string{"00:00:5e:00:53:01"},
			LANMacs: []string{"00:00:5e:00:53:02"}}, true},
	}
	for _, c := range cases {
		if got := c.a.Assigned(); got != c.want {
			t.Errorf("%s: Assigned() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNeedsWizard(t *testing.T) {
	assigned := RolesConf{Assignment: RoleAssignment{
		WANIfs: []string{"eth0"}, LANIfs: []string{"eth1"}}}
	cases := []struct {
		name string
		s    RolesStatus
		want bool
	}{
		{"no profile", RolesStatus{}, false},
		{"profile, no conf", RolesStatus{ProfilePresent: true}, true},
		{"profile, unassigned conf", RolesStatus{ProfilePresent: true, ConfPresent: true}, true},
		{"profile, assigned", RolesStatus{ProfilePresent: true, ConfPresent: true,
			Parsed: assigned}, false},
	}
	for _, c := range cases {
		if got := c.s.NeedsWizard(); got != c.want {
			t.Errorf("%s: NeedsWizard() = %v, want %v", c.name, got, c.want)
		}
	}
}

// roles.conf is sourced by bash, so nothing shell can interpret may ever be
// rendered into it. This is the wizard's injection guard.
func TestRenderRefusesShellInjection(t *testing.T) {
	badNames := []string{
		"", "eth0; rm -rf /", "$(reboot)", "`reboot`", "eth0 eth1",
		`eth0"`, "eth0'", "eth0\nLAN_IFS=x", "-eth0", ".hidden",
		"waaaaaaaytoolongname", "eth0$IFS",
	}
	for _, name := range badNames {
		conf := RolesConf{Assignment: RoleAssignment{
			WANIfs: []string{name}, LANIfs: []string{"eth1"}}}
		if _, err := RenderRolesConf(conf); err == nil {
			t.Errorf("RenderRolesConf accepted interface name %q", name)
		}
	}
	badMacs := []string{
		"", "00:00:5e:00:53", "00:00:5E:00:53:AA", "zz:00:5e:00:53:01",
		"00:00:5e:00:53:01; reboot", "$(x)", "00-00-5e-00-53-01",
	}
	for _, mac := range badMacs {
		conf := RolesConf{Assignment: RoleAssignment{
			WANIfs: []string{"eth0"}, LANMacs: []string{mac}}}
		if _, err := RenderRolesConf(conf); err == nil {
			t.Errorf("RenderRolesConf accepted MAC %q", mac)
		}
	}
}

func TestRenderedConfIsPlainAssignments(t *testing.T) {
	text, err := RenderRolesConf(RolesConf{Assignment: RoleAssignment{
		WANIfs: []string{"enp1s0"}, LANIfs: []string{"enp2s0", "enp3s0"}}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !rolesLine.MatchString(line) {
			t.Errorf("rendered line %q is not a plain KEY=value assignment", line)
		}
	}
	if !strings.Contains(text, `LAN_IFS="enp2s0 enp3s0"`) {
		t.Errorf("rendered conf lacks the quoted LAN set:\n%s", text)
	}
}

// The revert builder is the anti-lockout mechanism, so its output is asserted
// literally: a fully constant argv, no operator input anywhere in it.
func TestRevertScheduleArgv(t *testing.T) {
	want := []string{
		"systemd-run",
		"--on-active=120",
		"--unit=tui-router-roles-revert",
		"sh", "-c",
		"cp /etc/omarchy/router/roles.conf.prev /etc/omarchy/router/roles.conf" +
			" && omarchy-router-nics --apply",
	}
	if got := RevertScheduleArgv(RevertDelay); !reflect.DeepEqual(got, want) {
		t.Errorf("RevertScheduleArgv(RevertDelay) =\n %q\nwant\n %q", got, want)
	}
}

func TestRevertScheduleDelayRendering(t *testing.T) {
	cases := []struct {
		delay time.Duration
		want  string
	}{
		{120 * time.Second, "--on-active=120"},
		{90 * time.Second, "--on-active=90"},
		// A zero or sub-second delay clamps to one second: a revert that
		// fires "never" would defeat the whole mechanism.
		{0, "--on-active=1"},
		{100 * time.Millisecond, "--on-active=1"},
	}
	for _, c := range cases {
		argv := RevertScheduleArgv(c.delay)
		if argv[1] != c.want {
			t.Errorf("delay %v rendered %q, want %q", c.delay, argv[1], c.want)
		}
	}
}

func TestCancelRevertArgv(t *testing.T) {
	want := []string{"systemctl", "stop",
		"tui-router-roles-revert.timer", "tui-router-roles-revert.service"}
	if got := CancelRevertArgv(); !reflect.DeepEqual(got, want) {
		t.Errorf("CancelRevertArgv() = %q, want %q", got, want)
	}
}

func TestManualRevertInstructionsNameTheCommands(t *testing.T) {
	text := strings.Join(ManualRevertInstructions(), "\n")
	for _, want := range []string{
		"cp " + RolesPrevPath + " " + RolesConfPath,
		"omarchy-router-nics --apply",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("manual revert instructions lack %q:\n%s", want, text)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	oldText := "WAN_IFS=\"\"\nLAN_IFS=\"\"\nLAN_DHCP=\"yes\"\n"
	newText := "WAN_IFS=\"eth0\"\nLAN_IFS=\"eth1\"\nLAN_DHCP=\"yes\"\n"
	diff := UnifiedDiff("roles.conf", oldText, newText)
	for _, want := range []string{
		"--- roles.conf (current)",
		"+++ roles.conf (new)",
		"-WAN_IFS=\"\"",
		"+WAN_IFS=\"eth0\"",
		"+LAN_IFS=\"eth1\"",
		" LAN_DHCP=\"yes\"",
	} {
		if !strings.Contains(diff, want) {
			t.Errorf("diff lacks %q:\n%s", want, diff)
		}
	}
}

func TestParseUpdateCheckDefensively(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Updates
	}{
		{"good", `{"pending": 7, "security": 2}`,
			Updates{Available: true, Pending: 7, Security: 2}},
		{"zero is up to date", `{"pending": 0, "security": 0}`,
			Updates{Available: true}},
		{"not json", "boom",
			Updates{Reason: "unreadable tui-update --check output"}},
		{"missing pending", `{"security": 1}`,
			Updates{Reason: "tui-update --check reported no pending count"}},
		{"negative", `{"pending": -1}`,
			Updates{Reason: "tui-update --check reported a negative count"}},
		{"its own read failed", `{"pending": 0, "pendingError": "apt is locked"}`,
			Updates{Reason: "apt is locked"}},
	}
	for _, c := range cases {
		if got := ParseUpdateCheck(c.in); got != c.want {
			t.Errorf("%s: ParseUpdateCheck = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestUpdatesCard(t *testing.T) {
	cases := []struct {
		name    string
		updates Updates
		status  Status
		summary string
	}{
		{"absent", Updates{Reason: "tui-update not installed"},
			StatusUnknown, "tui-update not installed"},
		{"clean", Updates{Available: true}, StatusOK, "up to date"},
		{"pending", Updates{Available: true, Pending: 3},
			StatusInfo, "3 pending"},
		{"security", Updates{Available: true, Pending: 5, Security: 2},
			StatusWarn, "5 pending · 2 security"},
	}
	for _, c := range cases {
		card := updatesCard(Snapshot{Updates: c.updates})
		if card.Status != c.status || card.Summary != c.summary {
			t.Errorf("%s: card = %q/%q, want %q/%q",
				c.name, card.Status, card.Summary, c.status, c.summary)
		}
	}
}

// The demo backend walks the wizard's whole sequence without touching the
// machine, and its state moves the way the real one would.
func TestFakeWalksTheWizardSequence(t *testing.T) {
	ctx := context.Background()
	f := NewFake()

	status := f.readRoles()
	if !status.NeedsWizard() {
		t.Fatal("a fresh demo router should need the wizard (safe mode)")
	}

	content, err := RenderRolesConf(RolesConf{
		Assignment: RoleAssignment{WANIfs: []string{"eth0"}, LANIfs: []string{"eth1"}},
		Extras:     status.Parsed.Extras,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := f.WriteRoles(ctx, content); err != nil {
		t.Fatalf("write: %v", err)
	}
	after := f.readRoles()
	if after.NeedsWizard() {
		t.Error("after the write the demo should no longer need the wizard")
	}
	// The write carried the demo's LAN_ADDRESS/LAN_DHCP extras through.
	if len(after.Parsed.Extras) == 0 {
		t.Error("the demo's extra settings were dropped by the write")
	}

	preview, err := f.NicsPreview(ctx)
	if err != nil || !strings.Contains(preview, "WAN  eth0") {
		t.Errorf("nics preview = %q, %v; want it to resolve WAN to eth0", preview, err)
	}

	plan := f.ApplyPlan()
	if !plan.HasSystemdRun || plan.SchedulePreview == "" || plan.CancelPreview == "" {
		t.Errorf("demo apply plan should preview the full revert sequence: %+v", plan)
	}
	result, err := f.ApplyRoles(ctx, status.Content)
	if err != nil || !result.RevertScheduled {
		t.Errorf("demo apply = %+v, %v; want a scheduled revert", result, err)
	}
	if err := f.CancelRevert(ctx); err != nil {
		t.Errorf("demo cancel revert: %v", err)
	}
	if f.roles.revertScheduled || !f.roles.revertCancelled {
		t.Error("cancelling should disarm the demo's revert")
	}
}

func TestFakeByMACPinningResolves(t *testing.T) {
	ctx := context.Background()
	f := NewFake()
	content, err := RenderRolesConf(RolesConf{Assignment: RoleAssignment{
		WANMacs: []string{"00:00:5e:00:53:10"},
		LANIfs:  []string{"eth1"},
	}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := f.WriteRoles(ctx, content); err != nil {
		t.Fatalf("write: %v", err)
	}
	preview, err := f.NicsPreview(ctx)
	if err != nil || !strings.Contains(preview, "WAN  eth0") {
		t.Errorf("a MAC-pinned WAN should resolve to eth0, got %q, %v", preview, err)
	}
}

func FuzzParseRolesConf(f *testing.F) {
	f.Add(demoRolesConf)
	f.Add("WAN_IFS=eth0\nLAN_IFS='a b'\ngarbage\n")
	f.Fuzz(func(t *testing.T, text string) {
		conf := ParseRolesConf(text)
		// Whatever came in, a valid assignment must render back losslessly;
		// an invalid one must be refused, never rendered.
		if out, err := RenderRolesConf(conf); err == nil {
			if !reflect.DeepEqual(ParseRolesConf(out), conf) {
				t.Errorf("round trip changed %+v", conf)
			}
		}
	})
}

func FuzzParseUpdateCheck(f *testing.F) {
	f.Add(`{"pending": 1, "security": 0}`)
	f.Add(`]`)
	f.Fuzz(func(t *testing.T, text string) {
		u := ParseUpdateCheck(text)
		if u.Available && (u.Pending < 0 || u.Security < 0) {
			t.Errorf("an available reading must never carry a negative count: %+v", u)
		}
		if !u.Available && u.Reason == "" {
			t.Errorf("an unavailable reading must carry a reason: %+v", u)
		}
	})
}
