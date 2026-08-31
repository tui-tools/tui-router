package backup

import (
	"errors"
	"strings"
	"sync"
	"time"
)

// This file replicates the connectivity-safe atomic apply of tui-firewall's
// nftables staging package (tui-firewall/internal/nftables/staging). It is
// replicated rather than imported because tui-firewall is a separate module,
// and the mechanism — snapshot the live ruleset, apply the new one as one
// `nft -f` transaction, arm a keep-timer, and auto-roll-back if the operator
// does not confirm they still have access — is exactly what a router restore
// needs so a bad ruleset cannot lock the operator out. Credit: the design and
// the flush-and-replay rollback are lifted from that package.
//
// Like the original, this holds no exec: it renders the two payloads the flow
// needs and drives the timer, and the caller (the backend, the single exec
// site) runs the `nft -f` commands.

// DefaultKeepTimeout is how long the applied ruleset waits for the operator to
// confirm connectivity before it rolls itself back. It mirrors the firewall's
// "apply, then keep or revert" default.
const DefaultKeepTimeout = 60 * time.Second

// KeepPhase is where a KeepSession is in its lifecycle.
type KeepPhase int

const (
	// KeepBuilding: nothing has been applied yet.
	KeepBuilding KeepPhase = iota
	// KeepAwaiting: the new ruleset was applied and the session is waiting for
	// the operator to Commit before the timer rolls it back.
	KeepAwaiting
)

// Timer is the part of a countdown a KeepSession drives. A test swaps the real
// one for a timer it fires by hand.
type Timer interface {
	// Stop cancels the countdown. It is safe to call more than once.
	Stop()
}

// NewTimer starts a countdown that calls f after d unless it is stopped first.
type NewTimer func(d time.Duration, f func()) Timer

// realTimer wraps time.Timer to satisfy Timer.
type realTimer struct{ t *time.Timer }

func (r realTimer) Stop() { r.t.Stop() }

// RealTimer is the production countdown: time.AfterFunc.
func RealTimer(d time.Duration, f func()) Timer {
	return realTimer{t: time.AfterFunc(d, f)}
}

// KeepSession is the connectivity-safe apply lifecycle for one nftables
// ruleset. New builds it with the ruleset to apply and the snapshot to restore;
// the caller runs ApplyPayload, calls Arm, and then either Commit (the operator
// still has access) or lets the timer fire Rollback.
type KeepSession struct {
	mu       sync.Mutex
	timeout  time.Duration
	newTimer NewTimer

	target   string
	snapshot string
	phase    KeepPhase
	timer    Timer
	onExpire func()
}

// NewKeepSession builds a session that will apply target and, on rollback,
// replay snapshot. A zero or negative timeout uses DefaultKeepTimeout.
func NewKeepSession(target, snapshot string, timeout time.Duration) *KeepSession {
	if timeout <= 0 {
		timeout = DefaultKeepTimeout
	}
	return &KeepSession{
		timeout: timeout, newTimer: RealTimer,
		target: target, snapshot: snapshot,
	}
}

// SetTimer replaces the countdown factory, so a test can drive the timeout by
// hand. It must be called before Arm.
func (s *KeepSession) SetTimer(f NewTimer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newTimer = f
}

// Timeout is the keep-confirmation timeout in force.
func (s *KeepSession) Timeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.timeout
}

// Phase reports where the session is in its lifecycle.
func (s *KeepSession) Phase() KeepPhase {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.phase
}

// ApplyPayload renders the atomic transaction that installs the new ruleset:
// `flush ruleset` followed by the target, so nft reads it as one all-or-nothing
// step. The caller feeds this to `nft -f -`.
func (s *KeepSession) ApplyPayload() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return flushAndReplay(s.target)
}

// RollbackPayload renders the transaction that restores the pre-apply snapshot,
// the same flush-and-replay shape, so the machine ends exactly where it was.
func (s *KeepSession) RollbackPayload() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return flushAndReplay(s.snapshot)
}

// Arm records that the new ruleset was applied and starts the keep-confirmation
// countdown. If the operator does not Commit before it fires, onExpire is
// called — the caller's cue to run the rollback payload. A nil onExpire arms no
// timer: the caller drives the timeout itself and still gets the Awaiting phase.
func (s *KeepSession) Arm(onExpire func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == KeepAwaiting {
		return errors.New("staging: a ruleset is already awaiting confirmation")
	}
	s.phase = KeepAwaiting
	s.onExpire = onExpire
	if onExpire != nil && s.newTimer != nil {
		s.timer = s.newTimer(s.timeout, s.fire)
	}
	return nil
}

// fire is the timer callback: it rolls back only if nothing committed first.
func (s *KeepSession) fire() {
	s.mu.Lock()
	if s.phase != KeepAwaiting {
		s.mu.Unlock()
		return
	}
	cb := s.onExpire
	s.mu.Unlock()
	if cb != nil {
		cb()
	}
}

// Commit confirms the operator still has access: it stops the countdown and
// returns to Building. The applied ruleset stays in place.
func (s *KeepSession) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != KeepAwaiting {
		return errors.New("staging: nothing is awaiting confirmation")
	}
	s.reset()
	return nil
}

// Rollback stops the countdown and returns to Building; the caller runs the
// RollbackPayload to restore the snapshot. It reports whether there was an
// applied ruleset to roll back.
func (s *KeepSession) Rollback() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase != KeepAwaiting {
		return errors.New("staging: nothing was applied to roll back")
	}
	s.reset()
	return nil
}

// reset stops the timer and returns to Building. The caller holds the lock.
func (s *KeepSession) reset() {
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = nil
	s.onExpire = nil
	s.phase = KeepBuilding
}

// flushAndReplay builds a `nft -f` payload that empties the ruleset and rebuilds
// it from text, in one atomic transaction. The leading flush is what makes it a
// restore rather than a merge.
func flushAndReplay(ruleset string) string {
	payload := "flush ruleset\n"
	if trimmed := strings.TrimRight(ruleset, "\n"); trimmed != "" {
		payload += trimmed + "\n"
	}
	return payload
}
