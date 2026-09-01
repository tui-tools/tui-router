package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-router/internal/backup"
)

// The fixed locations the router profile owns. Collection reads these; a
// restore writes back to the same paths. They are a closed set, never derived
// from artifact input, so a restore can never be steered to write elsewhere.
const (
	networkdEtcDir    = "/etc/systemd/network"
	wireguardEtcDir   = "/etc/wireguard"
	dnsmasqRouterConf = "/etc/dnsmasq.d/router.conf"
	dnsmasqMainConf   = "/etc/dnsmasq.conf"
	// sysctlRouterConf is the profile's forwarding drop-in: without it a
	// restored machine has every rule and unit but forwards nothing.
	sysctlRouterConf = "/etc/sysctl.d/30-omarchy-router.conf"
	// resolvedRouterConf is the profile's systemd-resolved drop-in.
	resolvedRouterConf = "/etc/systemd/resolved.conf.d/30-omarchy-router.conf"
	// firewallRulesPath is tui-firewall's saved ruleset, kept in the router
	// profile's own directory. It is captured when that tool manages this
	// machine's firewall, so a restore gives it back its source of truth.
	firewallRulesPath = RolesDir + "/tui-firewall.nft"
)

// Search paths for the binaries a restore's reload step needs. They are only
// ever used to build a previewed command; a machine that lacks one simply gets
// no step for it.
var (
	networkctlSearchPaths = []string{"/usr/bin/networkctl", "/bin/networkctl"}
	sysctlSearchPaths     = []string{"/usr/sbin/sysctl", "/sbin/sysctl", "/usr/bin/sysctl"}
	wgQuickSearchPaths    = []string{"/usr/bin/wg-quick", "/bin/wg-quick"}
	systemctlSearchPaths  = []string{"/usr/bin/systemctl", "/bin/systemctl"}
	dnsmasqSearchPaths    = []string{"/usr/sbin/dnsmasq", "/usr/bin/dnsmasq"}
)

// Hostname names this machine for an export.
func (r *Real) Hostname() string {
	name, err := os.Hostname()
	if err != nil || strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return name
}

// CollectSources reads every subsystem read-only. Each probe degrades to an
// empty value on error rather than failing the whole export: a router with no
// WireGuard still has a ruleset worth capturing.
func (r *Real) CollectSources(ctx context.Context) (backup.Sources, error) {
	src := backup.Sources{}

	if r.nft != nil && r.nft.Bin != "" {
		if out, err := r.nft.Read(ctx, "nft", "list", "ruleset"); err == nil {
			src.Nftables = out
		}
	}
	src.Networkd = readDirFiles(networkdEtcDir, ".network", ".link")
	src.DHCPDNS = readFirstFile(dnsmasqRouterConf, dnsmasqMainConf)
	src.Wireguard = collectWireguard()
	// The four supporting files. roles.conf goes through the profile's own
	// parser and renderer on the way in, so what the artifact carries is the
	// canonical form — two exports of the same assignment are byte-identical
	// even if one machine's file was hand-edited.
	if raw := readFirstFile(RolesConfPath); strings.TrimSpace(raw) != "" {
		if canonical, err := SafeRolesConf(raw); err == nil {
			src.Roles = canonical
		} else {
			// A roles.conf this tool would not write back is still worth
			// capturing verbatim: the export records the machine, and the
			// restore refuses it there, where the operator can see why.
			src.Roles = raw
		}
	}
	src.Sysctl = readFirstFile(sysctlRouterConf)
	src.Resolved = readFirstFile(resolvedRouterConf)
	src.FirewallRules = readFirstFile(firewallRulesPath)
	// Account enumeration is deferred to a later stage: the profile's own list
	// of router users is not yet declared, so a real export carries no
	// accounts rather than guessing at which of the machine's users are the
	// router's. The demo exercises the accounts part end to end.
	return src, nil
}

// collectWireguard reads each interface config and strips its key material
// before it is ever held in memory as a Source.
func collectWireguard() map[string]backup.WGConf {
	entries, err := os.ReadDir(wireguardEtcDir)
	if err != nil {
		return nil
	}
	out := map[string]backup.WGConf{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(wireguardEtcDir, e.Name())
		data, err := os.ReadFile(path) //nolint:gosec // path is under the fixed /etc/wireguard dir
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".conf")
		clean, keyRef, _ := backup.StripWireguard(string(data))
		if keyRef == "" {
			// Default the key slot to the interface's own config path, which is
			// where wg-quick keeps the material; it is a reference, not a key.
			keyRef = path
		}
		out[name] = backup.WGConf{Config: clean, KeyRef: keyRef}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NftablesSnapshot captures the live ruleset for the rollback.
func (r *Real) NftablesSnapshot(ctx context.Context) (string, error) {
	if r.nft == nil || r.nft.Bin == "" {
		return "", errors.New("nftables is not available on this machine")
	}
	return r.nft.Read(ctx, "nft", "list", "ruleset")
}

// ApplyNftables runs one atomic `nft -f -` transaction from stdin.
func (r *Real) ApplyNftables(ctx context.Context, payload string) error {
	if r.nft == nil || r.nft.Bin == "" {
		return errors.New("nftables is not available on this machine")
	}
	_, err := r.nft.Run(ctx, runner.Command{
		Argv:        []string{"nft", "-f", "-"},
		Description: "Apply the artifact's nftables ruleset atomically",
		Destructive: true,
		Stdin:       payload,
	})
	return err
}

// WriteConfig installs one config-file part via a privileged `tee`, the
// family's way of writing a file whose content must not appear in an argv.
func (r *Real) WriteConfig(ctx context.Context, subsystem, name, content string) error {
	path, err := configPath(subsystem, name)
	if err != nil {
		return err
	}
	if subsystem == backup.SubsystemRoles {
		// roles.conf is sourced by bash. Never write an artifact's bytes into
		// it: re-parse and re-render them, so only validated interface names
		// and MACs can reach the file.
		content, err = SafeRolesConf(content)
		if err != nil {
			return err
		}
	}
	if r.tee == nil || r.tee.Bin == "" {
		return errors.New("tee is not available to write config files")
	}
	if err := r.ensureDir(ctx, filepath.Dir(path)); err != nil {
		return err
	}
	_, err = r.tee.Run(ctx, runner.Command{
		Argv:        []string{"tee", path},
		Description: fmt.Sprintf("Write %s", path),
		Destructive: true,
		Stdin:       content,
	})
	return err
}

// ensureDir creates a parent directory when it does not exist, via mkdir -p
// through the tee runner's privilege (a directory create is a write too).
func (r *Real) ensureDir(ctx context.Context, dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil
	}
	// Reuse the tee runner's escalation to run mkdir -p; a missing parent for
	// /etc/systemd/network on a fresh machine must not fail the restore.
	mk, err := runner.New(runner.Options{
		Bin: "mkdir", SearchPaths: []string{"/usr/bin/mkdir", "/bin/mkdir"},
		SudoPrefix: r.tee.Privilege, PrivilegedReads: &privileged,
	})
	if err != nil {
		return err
	}
	_, err = mk.Run(ctx, runner.Command{
		Argv:        []string{"mkdir", "-p", dir},
		Description: "Create " + dir,
		Destructive: false,
	})
	return err
}

// configPath maps a subsystem and part name to the fixed on-disk path a
// restore writes. The name is a base filename the reader already sanitized; it
// is joined under a fixed directory and re-checked so it can never escape it.
func configPath(subsystem, name string) (string, error) {
	switch subsystem {
	case backup.SubsystemNetworkd:
		return safeJoin(networkdEtcDir, name)
	case backup.SubsystemWireguard:
		return safeJoin(wireguardEtcDir, name+".conf")
	case backup.SubsystemDHCPDNS:
		return dnsmasqRouterConf, nil
	case backup.SubsystemRoles:
		return RolesConfPath, nil
	case backup.SubsystemSysctl:
		return sysctlRouterConf, nil
	case backup.SubsystemResolved:
		return resolvedRouterConf, nil
	case backup.SubsystemFirewallRules:
		return firewallRulesPath, nil
	default:
		return "", fmt.Errorf("no config path for subsystem %q", subsystem)
	}
}

// safeJoin joins a base filename under a directory and refuses anything that is
// not a single segment inside it.
func safeJoin(dir, name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return "", fmt.Errorf("unsafe config name %q", name)
	}
	joined := filepath.Join(dir, name)
	if filepath.Dir(joined) != filepath.Clean(dir) {
		return "", fmt.Errorf("config name %q escapes %s", name, dir)
	}
	return joined, nil
}

// ApplyAccounts ensures each account's group and user exist. It is best-effort
// and idempotent: an account that already exists is left as it is, and no
// credential is set (stage 1 carries none).
func (r *Real) ApplyAccounts(ctx context.Context, accounts []backup.Account) error {
	if len(accounts) == 0 {
		return nil
	}
	if r.useradd == nil || r.useradd.Bin == "" {
		return errors.New("useradd is not available to provision accounts")
	}
	for _, a := range accounts {
		if a.Name == "" {
			continue
		}
		if r.groupadd != nil && r.groupadd.Bin != "" {
			// A pre-existing group is fine; ignore the "already exists" exit.
			_, _ = r.groupadd.Run(ctx, runner.Command{
				Argv:        []string{"groupadd", "-f", a.Name},
				Description: "Ensure group " + a.Name,
			})
		}
		_, _ = r.useradd.Run(ctx, runner.Command{
			Argv:        []string{"useradd", "-M", "-N", a.Name},
			Description: "Ensure user " + a.Name + " (no credential set)",
			Destructive: true,
		})
	}
	return nil
}

// ReloadPlan builds the ordered list of commands that make a restore's config
// files take effect. It is derived from the artifact, so a restore that
// carried no resolver drop-in never previews a resolved restart, and a machine
// without dnsmasq never previews a dnsmasq restart. Every step is rendered
// through the runner that will execute it, so the preview is the command.
//
// The order matters: the links come up first, then the services that bind to
// them, then the forwarding knobs, then the WireGuard interfaces that ride on
// top. The nftables ruleset is not here — it goes last, through the
// connectivity-safe keep-or-rollback flow the command layer drives.
func (r *Real) ReloadPlan(target backup.Sources) []ReloadStep {
	var steps []ReloadStep

	add := func(bin string, searchPaths []string, argv []string, description string, destructive bool) {
		if !runner.Available(bin, searchPaths...) {
			return
		}
		step := ReloadStep{Argv: argv, Description: description, Destructive: destructive}
		if rr, err := r.mutRunner(bin, searchPaths...); err == nil {
			step.Preview = rr.Preview(runner.Command{
				Argv: argv, Description: description, Destructive: destructive})
		} else {
			step.Preview = strings.Join(argv, " ")
		}
		steps = append(steps, step)
	}

	if len(target.Networkd) > 0 || strings.TrimSpace(target.Roles) != "" {
		add("networkctl", networkctlSearchPaths,
			[]string{"networkctl", "reload"},
			"Re-read the .network units the restore wrote", true)
	}
	if strings.TrimSpace(target.Resolved) != "" {
		add("systemctl", systemctlSearchPaths,
			[]string{"systemctl", "restart", "systemd-resolved"},
			"Pick up the restored resolver drop-in", false)
	}
	if strings.TrimSpace(target.DHCPDNS) != "" && runner.Available("dnsmasq", dnsmasqSearchPaths...) {
		add("systemctl", systemctlSearchPaths,
			[]string{"systemctl", "restart", "dnsmasq"},
			"Pick up the restored DHCP/DNS config", false)
	}
	if strings.TrimSpace(target.Sysctl) != "" {
		add("sysctl", sysctlSearchPaths,
			[]string{"sysctl", "--system"},
			"Apply the restored forwarding knobs", false)
	}
	for _, name := range sortedWireguardNames(target.Wireguard) {
		// A tunnel whose config changed has to be bounced to read it. Down
		// first, then up: wg-quick has no reload, and an interface that was
		// not up simply fails the down, which the caller tolerates.
		add("wg-quick", wgQuickSearchPaths,
			[]string{"wg-quick", "down", name},
			"Take "+name+" down before its restored config is read", true)
		add("wg-quick", wgQuickSearchPaths,
			[]string{"wg-quick", "up", name},
			"Bring "+name+" up on the restored config", true)
	}
	return steps
}

// RunReload executes one previewed step. A wg-quick down on an interface that
// was not up is not a failure of the restore — the point of the down is to
// guarantee the following up reads the new config — so it is reported as
// tolerated rather than propagated.
func (r *Real) RunReload(ctx context.Context, step ReloadStep) error {
	if len(step.Argv) == 0 {
		return errors.New("reload step has no command")
	}
	bin := step.Argv[0]
	var searchPaths []string
	switch bin {
	case "networkctl":
		searchPaths = networkctlSearchPaths
	case "systemctl":
		searchPaths = systemctlSearchPaths
	case "sysctl":
		searchPaths = sysctlSearchPaths
	case "wg-quick":
		searchPaths = wgQuickSearchPaths
	default:
		return fmt.Errorf("%q is not one of the reload commands this tool runs", bin)
	}
	rr, err := r.mutRunner(bin, searchPaths...)
	if err != nil {
		return err
	}
	_, err = rr.Run(ctx, runner.Command{
		Argv: step.Argv, Description: step.Description, Destructive: step.Destructive})
	if err != nil && bin == "wg-quick" && len(step.Argv) > 1 && step.Argv[1] == "down" {
		return nil
	}
	return err
}

// LinkNames reads `ip -j link` for the names this machine's NICs carry now.
func (r *Real) LinkNames(ctx context.Context) ([]string, error) {
	if r.ip == nil || r.ip.Bin == "" {
		return nil, errors.New("iproute2 is not available to list the interfaces")
	}
	out, err := r.ip.Read(ctx, "ip", "-j", "link")
	if err != nil {
		return nil, err
	}
	return ParseLinkNames(out), nil
}

// sortedWireguardNames orders the artifact's WireGuard interfaces, so the
// reload plan is the same list every time it is previewed.
func sortedWireguardNames(m map[string]backup.WGConf) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// readDirFiles reads every file in dir whose name ends in one of the suffixes,
// returning a base-name-to-content map. A directory it cannot read yields nil.
func readDirFiles(dir string, suffixes ...string) map[string]string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !hasAnySuffix(e.Name(), suffixes) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // dir is a fixed /etc location
		if err != nil {
			continue
		}
		out[e.Name()] = string(data)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// readFirstFile returns the content of the first readable path, or "".
func readFirstFile(paths ...string) string {
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil { //nolint:gosec // paths are a fixed set of config locations
			return string(data)
		}
	}
	return ""
}

// hasAnySuffix reports whether name ends in one of the suffixes.
func hasAnySuffix(name string, suffixes []string) bool {
	for _, s := range suffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}
