package router

import (
	"context"
	"sync"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// The updates card reads its count from `tui-update --check`, another family
// tool's machine-readable read path. That check shells out to the package
// manager, so it is far too heavy for the cockpit's 2-second refresh — the
// result is cached and re-read on its own, much slower clock.

// updatesRefresh is how often the pending count is re-read.
const updatesRefresh = 5 * time.Minute

// updatesCheckTimeout bounds one `tui-update --check`, which talks to a
// package manager that may be slow or wedged.
const updatesCheckTimeout = 25 * time.Second

// updatesCache holds the last reading and when it was taken.
type updatesCache struct {
	mu   sync.Mutex
	at   time.Time
	info Updates
}

// updates is the process-wide cache. It is package-level rather than a Real
// field so this feature stays out of the backend struct other work is
// editing; one process drives one machine, so one cache is the right scope.
var updates updatesCache

// readUpdates returns the cached pending-updates state, re-reading it when
// the cache is older than updatesRefresh.
func (r *Real) readUpdates(ctx context.Context) Updates {
	updates.mu.Lock()
	defer updates.mu.Unlock()
	if !updates.at.IsZero() && time.Since(updates.at) < updatesRefresh {
		return updates.info
	}
	updates.info = probeUpdates(ctx)
	updates.at = time.Now()
	return updates.info
}

// probeUpdates runs `tui-update --check` once and parses its JSON. Every
// failure degrades to a not-available state with a reason — a cockpit card,
// never an error that stops the screen.
func probeUpdates(ctx context.Context) Updates {
	if !available("tui-update") {
		return Updates{Reason: "tui-update not installed"}
	}
	// The runner previews and executes the same argv; --check is tui-update's
	// documented read-only path, safe against a production router.
	check, err := runner.New(runner.Options{
		Bin: "tui-update", Timeout: updatesCheckTimeout,
		PrivilegedReads: &unprivileged,
	})
	if err != nil {
		return Updates{Reason: "tui-update not installed"}
	}
	out, err := check.Read(ctx, "tui-update", "--check")
	if err != nil {
		return Updates{Reason: "tui-update --check failed"}
	}
	return ParseUpdateCheck(out)
}
