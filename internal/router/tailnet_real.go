package router

import (
	"context"
	"sync"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// The tailnet card reads its state from `tui-tailscale --check`, the
// self-hosted Tailscale tool's machine-readable read path. That check asks
// the tailscale client and headscale for their state, several programs each
// time, so it is cached and re-read on a slower clock than the cockpit's
// 2-second refresh, the same way the updates card treats tui-update.

// tailnetRefresh is how often the tailnet state is re-read.
const tailnetRefresh = time.Minute

// tailnetCheckTimeout bounds one `tui-tailscale --check`.
const tailnetCheckTimeout = 20 * time.Second

// TailnetNotInstalled is the card's summary when tui-tailscale is absent,
// worded like the tool foot of every other card.
const TailnetNotInstalled = "tui-tailscale (not installed)"

// tailnetCache holds the last reading and when it was taken.
type tailnetCache struct {
	mu   sync.Mutex
	at   time.Time
	info Tailnet
}

// tailnet is the process-wide cache; one process drives one machine.
var tailnet tailnetCache

// readTailnet returns the cached tailnet state, re-reading it when the cache
// is older than tailnetRefresh.
func (r *Real) readTailnet(ctx context.Context) Tailnet {
	tailnet.mu.Lock()
	defer tailnet.mu.Unlock()
	if !tailnet.at.IsZero() && time.Since(tailnet.at) < tailnetRefresh {
		return tailnet.info
	}
	tailnet.info = probeTailnet(ctx)
	tailnet.at = time.Now()
	return tailnet.info
}

// probeTailnet runs `tui-tailscale --check` once and parses its JSON. Every
// failure degrades to a not-available state with a reason: a cockpit card,
// never an error that stops the screen.
func probeTailnet(ctx context.Context) Tailnet {
	if !available("tui-tailscale") {
		return Tailnet{Reason: TailnetNotInstalled}
	}
	// --check is tui-tailscale's documented read-only path, safe against a
	// production router: it escalates its own reads with sudo -n, so the
	// cockpit runs it unprivileged.
	check, err := runner.New(runner.Options{
		Bin: "tui-tailscale", Timeout: tailnetCheckTimeout,
		PrivilegedReads: &unprivileged,
	})
	if err != nil {
		return Tailnet{Reason: TailnetNotInstalled}
	}
	out, err := check.Read(ctx, "tui-tailscale", "--check")
	if err != nil {
		return Tailnet{Reason: "tui-tailscale --check failed"}
	}
	return ParseTailscaleCheck(out)
}
