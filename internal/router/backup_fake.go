package router

import (
	"context"

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

	demoLanNetwork = `[Match]
Name=lan0

[Network]
Address=192.0.2.1/24
IPForward=yes
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
	}
	return nil
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
