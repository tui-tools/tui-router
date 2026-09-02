<!--
  tui-router — the read-only router cockpit.
  Part of the tui-tools family. See https://github.com/tui-tools.
-->

<p align="center">
  <img src="assets/logo.png" alt="tui-router" width="240">
</p>

# tui-router

Every part of the router on one screen.

tui-router is the read-only cockpit for a Linux router. It reads the machine
with cheap system probes and draws one card per area — the interfaces and their
WAN/LAN roles, the firewall's posture, live traffic per interface, the DHCP
server and its leases, the WireGuard peers — and refreshes them in place.

It changes nothing itself. Press ENTER on a card and tui-router suspends, hands
the terminal to the tool that manages that area — tui-firewall, tui-network,
tui-traffic, tui-vpn — and resumes when you leave it, the same handoff the
family launcher uses. The overview is here; the change happens in the tool the
card opens, behind that tool's own preview and confirm.

> Beta. Part of the tui-tools family and still under validation.

## The cards

| Card | What it reads | Managed by |
| --- | --- | --- |
| Interfaces | each link, up/down, its IPv4, and whether it looks like WAN (a default route) or LAN (an attached subnet) — from `ip -j addr` and `ip -j route` | tui-network |
| Firewall | which backend is active (firewalld, nftables or ufw) and a one-line posture: default policy, rule count, whether NAT masquerades | tui-firewall |
| Traffic | the live throughput per interface, a small `/proc/net/dev` delta refreshed on a timer | tui-traffic |
| DHCP | whether a DHCP server (dnsmasq or kea) is running, and how many leases it holds | tui-network |
| VPN | any WireGuard interface and its peer count (from `wg show`), and whether a headscale control plane is present | tui-vpn |
| Updates | the pending and security update counts, read from `tui-update --check` (cached, re-read every few minutes); "tui-update not installed" when the binary is absent | tui-update |

Every read is cheap and read-only. Most are unprivileged; the few that need
root — the nftables ruleset, `ufw status`, the WireGuard dump — escalate with
`sudo -n`, which never prompts. A card that cannot escalate reads *unknown* with
the reason, rather than failing the whole screen.

## The roles wizard (router profile)

A fresh [Omarchy Server](https://github.com/edimarlnx/omarchy-server) router
boots into safe mode: `/etc/omarchy/router/roles.conf` exists but assigns no
WAN or LAN role, so every port takes a DHCP lease and nothing is forwarded —
reachable, not open, and not locked out. Until now no tool in the family could
assign those roles. The cockpit closes that gap.

On a router-profile host whose roles are not both assigned, the cockpit shows
a banner and `w` opens the roles wizard:

1. **Select.** Every NIC is listed with its name, MAC, link state and current
   IP. Mark each one WAN, LAN or unassigned — a role is a set, so several WAN
   uplinks (failover) and several LAN ports (bridged into `br-lan`) are fine,
   and the same port may carry both. `m` pins a NIC's role to its MAC instead
   of its name, so the assignment survives a kernel rename.
2. **Preview the write.** The wizard shows a unified diff of `roles.conf`, the
   output of `omarchy-router-nics --preview` (run read-only), and the exact
   `install -m 644` command. Confirming writes the file — through a staged
   temp file, never a partial write — and nothing else.
3. **Preview the apply.** A second, danger-colored confirm shows every command
   of the apply sequence and warns that an SSH session may drop. Before the
   apply runs, the wizard stages the previous `roles.conf` as
   `roles.conf.prev` and arms a timed revert with `systemd-run`: unless
   connectivity is confirmed within 120 seconds, the previous assignment is
   restored and re-applied automatically. Then `omarchy-router-nics --apply`
   rewrites the `.network` units and reloads networkd.
4. **Confirm connectivity.** If the session held, one more previewed command
   (`systemctl stop tui-router-roles-revert.service …`) disarms the revert and
   the new mapping is permanent. If it did not, wait two minutes and the
   router comes back on the old assignment.

Where `systemd-run` is not available the wizard degrades honestly: no
automatic revert is armed, and the result screen prints the exact manual
revert commands instead.

Everything the wizard writes is validated first — interface names and MACs
only, in strict shapes — because `roles.conf` is sourced by shell and must
never carry anything shell could interpret. `--demo` walks the whole wizard
against the sample router, running nothing.

## Reboot and poweroff

`B` reboots and `P` powers off, each behind a typed confirm: the dialog shows
the exact `systemctl` command and runs it only after you type the action's own
name (`reboot` / `poweroff`). A router's power is the one thing heavier than
any card, so a plain y/n is not enough.

## Try it without installing anything

```sh
tui-router --demo
```

`--demo` drives a sample office router — two interfaces, an active firewall,
live traffic, a dnsmasq handing out leases, a WireGuard interface with peers,
a pending-updates count, and an unassigned roles.conf so the roles wizard can
be walked end to end — every card renders and every flow works on a machine
that has none of these backends installed. Nothing is read and nothing is
changed.

## Install

<!-- install:start -->
<!-- Generated by tui-kit/tools/render-install.py from tool.json. -->
<!-- Edit the manifest, then run `make readme`. -->

### From source

```sh
git clone https://github.com/tui-tools/tui-router
cd tui-router && make demo
```

Or run it against a sample router with `tui-router --demo`, which needs nothing
installed.

Not packaged for these yet; the static binary works everywhere in the meantime.

### Arch Linux — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui-tools.github.io/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
curl -fsSL -o /tmp/tui-tools.asc https://pkgs.tui.tools/pubkey.asc
sudo pacman-key --add /tmp/tui-tools.asc
sudo pacman-key --lsign-key \
  "$(gpg --show-keys --with-colons /tmp/tui-tools.asc | awk -F: '/^fpr:/{print $10; exit}')"
printf '[tui-tools]\nServer = https://pkgs.tui.tools/arch/$arch\n' \
  | sudo tee -a /etc/pacman.conf
sudo pacman -Sy
```

Then, and for every other tool in the family:

```sh
sudo pacman -S tui-router
```

Available once tui-router's first release lands in pkgs.tui.tools.

### Debian and Ubuntu — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui-tools.github.io/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://pkgs.tui.tools/pubkey.asc \
  | sudo gpg --dearmor -o /etc/apt/keyrings/tui-tools.gpg
echo "deb [signed-by=/etc/apt/keyrings/tui-tools.gpg] https://pkgs.tui.tools/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/tui-tools.list
sudo apt update
```

Then, and for every other tool in the family:

```sh
sudo apt install tui-router
```

Available once tui-router's first release lands in pkgs.tui.tools.

### Fedora and RHEL — coming soon

Needs the tui-tools repository, which is a [one-time
setup](https://tui-tools.github.io/install/).

The one-liner detects the distribution and adds the repository and its signing
key:

```sh
curl -fsSL https://pkgs.tui.tools/install.sh | sh
```

Piping a script into a shell is not this family's style, so here is the same
setup by hand — read it, or read the script first with `curl -fsSL
https://pkgs.tui.tools/install.sh -o install.sh`:

```sh
sudo rpm --import https://pkgs.tui.tools/pubkey.asc
sudo curl -fsSL -o /etc/yum.repos.d/tui-tools.repo https://pkgs.tui.tools/rpm/tui-tools.repo
sudo dnf makecache
```

Then, and for every other tool in the family:

```sh
sudo dnf install tui-router
```

Available once tui-router's first release lands in pkgs.tui.tools.

### Any distribution, static binary — coming soon

```sh
curl -fsSL https://github.com/tui-tools/tui-router/releases/download/v0.2.0/tui-router_0.2.0_linux_amd64.tar.gz | tar -xz tui-router
sudo install -m0755 tui-router /usr/local/bin/tui-router
```

Available once tui-router is released.

### Verify a download

Every release of `tui-router` ships a `checksums.txt`. Check an archive against
it before installing:

```sh
sha256sum -c checksums.txt --ignore-missing
```
<!-- install:end -->

## Usage

```
tui-router [flags]
```

| Flag | What it does |
| --- | --- |
| `--demo` | run against a sample router, reading and changing nothing |
| `--check` | read every card once, print the result as JSON, and exit (no UI) |
| `--report` | print the versions and machine facts a bug report needs, then exit |
| `--theme PATH` | use an Omarchy-style `colors.toml` |
| `--sudo PREFIX` | privilege escalation prefix, e.g. `sudo -n`, or `""` to disable |
| `--version` | print the version and exit |

Keys: `↑`/`↓` select a card, `enter` opens the tool that manages it, `w` opens
the roles wizard (router profile), `b` opens the backup screen, `B`/`P`
reboot/poweroff behind a typed confirm, `r` re-reads the router now, `?` shows
help, `q` quits.

`--check` runs the read path only — never a handoff — so it is safe against a
live router. Its exit code reports whether the tool could read, never a verdict
about the machine: a router with no firewall is a successful run whose findings
travel in the JSON.

## Backup and restore

`tui-router export` writes one self-describing, integrity-checked artifact that
captures everything a router needs to be itself again:

| Subsystem | What travels |
| --- | --- |
| roles | `/etc/omarchy/router/roles.conf` — which ports play WAN and which play LAN |
| networkd | the `.network` / `.link` units from `/etc/systemd/network` |
| sysctl | `/etc/sysctl.d/30-omarchy-router.conf`, the forwarding knobs |
| resolved | `/etc/systemd/resolved.conf.d/30-omarchy-router.conf` |
| dhcp-dns | the dnsmasq config the router profile owns |
| wireguard | each interface's config, **key material stripped** and referenced by path |
| firewall-rules | tui-firewall's saved ruleset, when that tool manages this router |
| nftables | the live ruleset, as the plain form `nft -f` reloads |
| accounts | the router's own users and groups — names and roles only |

`tui-router restore` reads that artifact back, previews it, and applies it
after one explicit confirmation. The cockpit's `b` key runs both flows on
screen, with the same previews and the same confirmations; the subcommands stay
because a backup you can put in a cron job is worth more than one you can only
press a key for.

```
tui-router export  [--out FILE] [--sign KEY] [--demo]
tui-router restore FILE [--verify PUBKEY] [--dry-run] [--keep] [--demo]
```

| Flag | What it does |
| --- | --- |
| `export --out FILE` | write the artifact here (default `router-<host>-<stamp>.tuiback`) |
| `export --sign KEY` | add a detached Ed25519 signature over the checksum file |
| `restore --verify PUBKEY` | require a valid signature from this public key |
| `restore --dry-run` | verify and preview only; apply nothing |
| `restore --keep` | keep the restored ruleset without the connectivity confirmation |
| `--demo` | run the whole loop against the in-memory sample router, no root |

The artifact is a gzip'd tar (`.tuiback`) with a `manifest.json`, one part per
subsystem, an always-present `MANIFEST.sha256`, and — only when you pass a key —
a detached `SIGNATURE`. Integrity is unconditional: a single altered byte makes
restore refuse. A signature is optional and is checked only when you pass
`--verify`; no key is ever required, and no secret is ever written to disk or
into the artifact. WireGuard key material is stripped from the config and
referenced by path — you provision it out of band — and accounts carry no
credential hashes in this stage.

`restore` never applies silently. It shows a per-subsystem diff, then the exact
reload commands it will run, then takes one typed confirmation. What runs, in
order:

1. **The config files land.** Every subsystem the artifact carries is written
   to its fixed path — the paths are a closed set in the backend, never derived
   from the artifact, so a crafted file cannot steer a write elsewhere.
   `roles.conf` is re-parsed and re-rendered through the profile's own
   validator on the way in: it is sourced by shell, so only validated interface
   names and MACs can ever reach it.
2. **What was written is reloaded** — `networkctl reload`, `systemctl restart
   systemd-resolved`, `systemctl restart dnsmasq` (when dnsmasq is installed),
   `sysctl --system`, and `wg-quick down`/`up` for each restored WireGuard
   interface. Every one of these is previewed before the confirmation, and the
   ones that can drop your session are marked. A file on disk that nothing
   re-read is not a restored router.
3. **The ruleset applies last,** as one atomic `nft -f` transaction with a
   connectivity-safe rollback: the live ruleset is snapshotted first, and if
   you do not confirm within 60 seconds that you still have access, it reverts
   on its own. That is why nftables goes last — a bad ruleset is what locks an
   operator out, and by then everything else is already in place.

`--dry-run` stops after the preview.

**Scripted restores.** The keep confirmation is read from stdin, so
`printf 'yes\nkeep\n' | tui-router restore FILE` works. A restore nobody is
sitting in front of can skip the 60-second window with `--keep`, which keeps
the ruleset the moment it applies. It is for scripted restores or a local
console: it bypasses the connectivity guard, so only use it when you can reach
the box another way. Without it the default is unchanged — silence rolls back.

**Restoring onto different hardware.** If the artifact's `roles.conf` assigns
roles to ports this machine does not have — a new box whose NICs are named
`enp1s0` where the old one had `eth0` — the restore says so, names the ports
that are missing and the ones this machine actually has, and requires a second
confirmation typed as `different hardware` before the ordinary one. Restoring
as-is is legal and sometimes right; it must not be an accident. Pinning roles
by MAC in the roles wizard (`m`) is what makes an assignment survive a rename
in the first place.

## The contract

The cards are read-only: every per-area change belongs to the tool a card
hands off to, through that tool's preview-and-confirm. The cockpit itself
carries exactly four mutations — the roles wizard, reboot, poweroff and
`restore` — and each one shows the literal command line or the file diff before
a confirm, with the wizard's apply and the restore's nftables step additionally
staging their own timed revert first. The one place this binary starts a
process is its backend package — the read-only probes, the handoff exec, and
these previewed commands — which is what the family's exec boundary requires.

The handoff is Bubble Tea's `tea.Exec`: the cockpit suspends, the child tool
takes over the terminal, and the cockpit resumes and re-reads the machine when
the child exits — because after another tool has run, the screen has to show
the machine, not what it remembered of it.

## Compatibility

<!-- compat:start -->
<!-- Generated by tui-kit/tools/render-compat.py from tool.json. -->
<!-- Edit the manifest, then run `make readme`. -->

`tui-router` probes its backend once at startup and shows the version in the
header. A version nobody has tested is marked `(untested)` there rather than
hidden; one below the minimum is marked as such and the tool still runs.

### iproute2

| | |
| --- | --- |
| Binary | `ip` |
| Version read with | `ip -V` |
| Minimum | 5.0 |
| Tested | none yet |
| Version-gated features | `json-output` (since 4.13) |

| Versions | What changes |
| --- | --- |
| `<4.13` | `ip -j` (JSON output) is missing, so the interface and route cards cannot be read from this version |

### nftables

| | |
| --- | --- |
| Binary | `nft` |
| Version read with | `nft -v` |
| Minimum | 0.9 |
| Tested | none yet |

### wireguard-tools

| | |
| --- | --- |
| Binary | `wg` |
| Version read with | `wg --version` |
| Minimum | 1.0 |
| Tested | none yet |

The tested versions are generated from `compat/results.jsonl`, which the tool's
own smoke test appends to when it runs against a real machine in
[tui-lab](https://github.com/tui-tools/tui-lab).
<!-- compat:end -->

## Contributing

Bug reports start with the output of `tui-router --report`: it names the
versions and the machine, and carries no hostname, user name, home path or
address. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
