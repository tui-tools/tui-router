package router

import (
	"context"
	"strings"

	"github.com/tui-tools/tui-router/internal/backup"
)

// The demo's canned logical state. Every address is in a documentation range
// (RFC 5737 / RFC 3849) or the 10.0.0.0/8 lab range, so the fixtures carry
// nothing routable. demoWireguardConf holds fake key material on purpose, to
// exercise the collector's stripping.
const (
	demoNftRuleset = `table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		ct state established,related accept
		iif "lo" accept
		tcp dport 22 accept
	}
	chain forward {
		type filter hook forward priority 0; policy drop;
		ct state established,related accept
		iif "lan0" oif "wan0" accept
	}
}
table ip nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oif "wan0" masquerade
	}
}
`

	demoWanNetwork = `[Match]
Name=wan0

[Network]
DHCP=yes
`

	// The demo LAN unit hands out the leases itself, the way an Omarchy
	// Router's does: DHCPServer=yes in [Network], the pool carved out of the
	// unit's own Address= by the [DHCPServer] offsets.
	demoLanNetwork = `[Match]
Name=lan0

[Network]
Address=192.0.2.1/24
IPForward=yes
DHCPServer=yes

[DHCPServer]
PoolOffset=100
PoolSize=101
EmitDNS=yes
DNS=192.0.2.1
`

	demoDnsmasqConf = `interface=lan0
dhcp-range=192.0.2.100,192.0.2.200,12h
domain=lan.example
`

	demoWireguardConf = `[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = ` + DemoWireguardSecret + `
# KeyRef: /etc/wireguard/wg0.key

[Peer]
PublicKey = AbCdEf0123456789AbCdEf0123456789AbCdEf01234=
AllowedIPs = 10.0.0.2/32
`

	demoSysctlConf = `net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
`

	demoResolvedConf = `[Resolve]
DNS=192.0.2.1
DNSStubListener=no
`

	demoFirewallRules = `# Saved by tui-firewall.
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
	}
}
`
)

// Hostname names the demo router.
func (f *Fake) Hostname() string { return "demo-router" }

// CollectSources returns the demo's logical state, stripping the WireGuard key
// material exactly as the real collector does — so what the demo exports is
// already free of secrets.
func (f *Fake) CollectSources(_ context.Context) (backup.Sources, error) {
	src := backup.Sources{
		Nftables: f.nft,
		DHCPDNS:  f.dhcpDNS,
	}
	if len(f.networkd) > 0 {
		src.Networkd = map[string]string{}
		for k, v := range f.networkd {
			src.Networkd[k] = v
		}
	}
	if len(f.rawWG) > 0 {
		src.Wireguard = map[string]backup.WGConf{}
		for name, raw := range f.rawWG {
			clean, keyRef, _ := backup.StripWireguard(raw)
			src.Wireguard[name] = backup.WGConf{Config: clean, KeyRef: keyRef}
		}
	}
	if len(f.accounts) > 0 {
		src.Accounts = append([]backup.Account(nil), f.accounts...)
	}
	// The role assignment comes from the demo's one roles.conf — the same file
	// the wizard edits — canonicalised the way the real collector does.
	if f.roles != nil && strings.TrimSpace(f.roles.content) != "" {
		if canonical, err := SafeRolesConf(f.roles.content); err == nil {
			src.Roles = canonical
		} else {
			src.Roles = f.roles.content
		}
	}
	src.Sysctl = f.sysctl
	src.Resolved = f.resolved
	src.FirewallRules = f.firewallNFT
	return src, nil
}

// NftablesSnapshot returns the demo's current ruleset.
func (f *Fake) NftablesSnapshot(_ context.Context) (string, error) { return f.nft, nil }

// ApplyNftables installs a flush-and-replay payload into the demo's state by
// keeping everything after the leading `flush ruleset` line, which is what the
// real nft would end up holding.
func (f *Fake) ApplyNftables(_ context.Context, payload string) error {
	f.nft = stripFlush(payload)
	return nil
}

// WriteConfig installs one config-file part into the demo's in-memory disk. The
// WireGuard write stores the config as the artifact carried it (no key line),
// which is exactly what a real restore lands before the material is provisioned
// out of band.
func (f *Fake) WriteConfig(_ context.Context, subsystem, name, content string) error {
	switch subsystem {
	case backup.SubsystemNetworkd:
		if f.networkd == nil {
			f.networkd = map[string]string{}
		}
		f.networkd[name] = content
	case backup.SubsystemDHCPDNS:
		f.dhcpDNS = content
	case backup.SubsystemWireguard:
		if f.rawWG == nil {
			f.rawWG = map[string]string{}
		}
		f.rawWG[name] = content
	case backup.SubsystemRoles:
		// The demo re-renders roles.conf through the profile's validator too,
		// so --demo exercises the injection guard the real write relies on.
		safe, err := SafeRolesConf(content)
		if err != nil {
			return err
		}
		if f.roles == nil {
			f.roles = &fakeRoles{}
		}
		f.roles.content = safe
	case backup.SubsystemSysctl:
		f.sysctl = content
	case backup.SubsystemResolved:
		f.resolved = content
	case backup.SubsystemFirewallRules:
		f.firewallNFT = content
	}
	return nil
}

// ReloadPlan mirrors the real plan step for step, so --demo previews exactly
// the sequence a real restore would run — with every line marked as the demo's,
// and nothing behind it.
func (f *Fake) ReloadPlan(target backup.Sources) []ReloadStep {
	var steps []ReloadStep
	add := func(argv []string, description string, destructive bool) {
		steps = append(steps, ReloadStep{
			Argv:        argv,
			Preview:     strings.Join(argv, " ") + " (demo: not run)",
			Description: description,
			Destructive: destructive,
		})
	}
	if len(target.Networkd) > 0 || strings.TrimSpace(target.Roles) != "" {
		add([]string{"networkctl", "reload"},
			"Re-read the .network units the restore wrote", true)
	}
	if strings.TrimSpace(target.Resolved) != "" {
		add([]string{"systemctl", "restart", "systemd-resolved"},
			"Pick up the restored resolver drop-in", false)
	}
	if strings.TrimSpace(target.DHCPDNS) != "" {
		add([]string{"systemctl", "restart", "dnsmasq"},
			"Pick up the restored DHCP/DNS config", false)
	}
	if strings.TrimSpace(target.Sysctl) != "" {
		add([]string{"sysctl", "--system"}, "Apply the restored forwarding knobs", false)
	}
	for _, name := range sortedWireguardNames(target.Wireguard) {
		add([]string{"wg-quick", "down", name},
			"Take "+name+" down before its restored config is read", true)
		add([]string{"wg-quick", "up", name},
			"Bring "+name+" up on the restored config", true)
	}
	return steps
}

// RunReload records the step and runs nothing.
func (f *Fake) RunReload(_ context.Context, step ReloadStep) error {
	f.reloads = append(f.reloads, strings.Join(step.Argv, " "))
	return nil
}

// Reloads is what the demo pretended to reload, for the round-trip test.
func (f *Fake) Reloads() []string { return append([]string(nil), f.reloads...) }

// LinkNames reports the demo router's NIC names.
func (f *Fake) LinkNames(_ context.Context) ([]string, error) {
	var names []string
	for _, iface := range demoInterfaces() {
		names = append(names, iface.Name)
	}
	return names, nil
}

// ApplyAccounts records the accounts in the demo's state.
func (f *Fake) ApplyAccounts(_ context.Context, accounts []backup.Account) error {
	f.accounts = append([]backup.Account(nil), accounts...)
	return nil
}

// stripFlush drops a single leading `flush ruleset` line from an nft payload,
// leaving the ruleset the demo should now hold.
func stripFlush(payload string) string {
	const marker = "flush ruleset\n"
	if len(payload) >= len(marker) && payload[:len(marker)] == marker {
		return payload[len(marker):]
	}
	return payload
}
