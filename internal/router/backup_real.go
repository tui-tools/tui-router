package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
