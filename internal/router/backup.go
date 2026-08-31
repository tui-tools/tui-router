package router

import (
	"context"

	"github.com/tui-tools/tui-router/internal/backup"
)

// BackupBackend is the boundary export and restore go through. Like the
// read-only Backend, it keeps every process start inside this package (the
// family's single exec site): the command layer orchestrates the preview,
// the confirmation and the keep-timer, and calls these methods to touch the
// machine. Both the real router and the in-memory demo implement it, so the
// whole export→restore loop runs with no root and no real router.
type BackupBackend interface {
	// Hostname names the machine an export was taken from. It is read here so
	// the pure backup package never has to.
	Hostname() string
	// CollectSources reads every subsystem read-only and returns the router's
	// logical identity, already scrubbed of secrets (WireGuard key material is
	// stripped and referenced by path).
	CollectSources(ctx context.Context) (backup.Sources, error)
	// NftablesSnapshot returns the live ruleset, captured before a restore so
	// the connectivity-safe rollback has something to replay.
	NftablesSnapshot(ctx context.Context) (string, error)
	// ApplyNftables runs one `nft -f -` transaction with the given payload
	// (a flush-and-replay script). It is all-or-nothing: nft applies the whole
	// script or none of it.
	ApplyNftables(ctx context.Context, payload string) error
	// WriteConfig installs one config-file part. subsystem is one of the
	// backup subsystem tags; name is the base filename for the multi-file
	// subsystems (networkd, wireguard) and empty for the single-file ones.
	WriteConfig(ctx context.Context, subsystem, name, content string) error
	// ApplyAccounts provisions the router's own users/groups by name and role.
	// Stage 1 carries no credential hashes, so this only ensures the accounts
	// exist; secrets are set out of band.
	ApplyAccounts(ctx context.Context, accounts []backup.Account) error
}
