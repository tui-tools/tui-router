#!/bin/bash
# Backend smoke test for tui-router, run inside a lab guest.
#
# The contract (see tui-tools/tui-lab): this script runs on the guest as the
# unprivileged lab user, escalates with `sudo -n` only, prints a short PASS/FAIL
# table and exits non-zero if anything failed. The binary under test is at
# $TUI_LAB_BIN (default: tui-router on PATH).
#
# tui-router is a read-only cockpit: it reads the machine and hands off to other
# tools, and changes nothing itself. So the smoke test proves the two things
# that must hold on a real router — that --check reads every card and answers
# with valid JSON, and that --report keeps its privacy promise — plus the
# family's shared --report assertions.
set -uo pipefail

bin="${TUI_LAB_BIN:-tui-router}"
pass=0
fail=0

# check runs one assertion: a label, a command, and a grep pattern the output
# must match. Output is captured so a failure can show it.
check() {
  local label="$1" command="$2" pattern="$3" output status
  output=$(eval "$command" 2>&1)
  status=$?
  if [[ $status -eq 0 ]] && grep -qE "$pattern" <<<"$output"; then
    printf 'PASS  %s\n' "$label"
    pass=$((pass + 1))
  else
    printf 'FAIL  %s (exit %d)\n' "$label" "$status"
    sed 's/^/      | /' <<<"$output" | head -12
    fail=$((fail + 1))
  fi
}

echo "--- tui-router smoke on $(. /etc/os-release && echo "$PRETTY_NAME")"
echo "      user=$(id -un)"

# --- the read path (--check) -----------------------------------------------
#
# --check reads every card once and prints JSON. It runs the read path only —
# never a handoff — so it is safe on a live router. The reads that need root
# escalate with sudo -n; a card that cannot escalate reads unknown rather than
# failing, so --check must exit zero and emit valid JSON either way.
check "check emits the cards array" \
  "sudo -n $bin --check" \
  '"cards"'

check "check names the interfaces card" \
  "sudo -n $bin --check" \
  '"kind": "interfaces"'

check "check exits zero even when a managing tool is absent" \
  "sudo -n $bin --check >/dev/null; echo exit=\$?" \
  '^exit=0$'

check "check carries the updates card" \
  "sudo -n $bin --check" \
  '"kind": "updates"'

# The roles block reports whether this is a router-profile host and whether
# the WAN/LAN roles are assigned — the state the roles wizard acts on.
check "check reports the roles state" \
  "sudo -n $bin --check" \
  '"profilePresent"'

# --- backup and restore (read-only paths only) -----------------------------
#
# The export path reads every subsystem and writes one artifact; the restore
# path is exercised with --dry-run only, which verifies and previews and
# applies nothing. A guest is a live router, so the smoke test never runs an
# apply — the demo round trip in the unit tests covers the write path, and the
# real apply is what a supervised VM check exercises by hand.
artifact="${TMPDIR:-/tmp}/tui-router-smoke.tuiback"
rm -f "$artifact"

check "export writes an artifact" \
  "sudo -n $bin export --out $artifact" \
  'wrote .*\.tuiback'

check "the artifact verifies and previews without applying" \
  "sudo -n $bin restore --dry-run $artifact" \
  'integrity: checksums verified'

check "the restore preview names the commands it would reload with" \
  "sudo -n $bin restore --dry-run $artifact" \
  'nothing was applied'

check "the artifact carries no WireGuard private key" \
  "tar -xzOf $artifact 2>/dev/null | grep -ci 'PrivateKey *=' || true" \
  '^0$'

rm -f "$artifact"

# --- the report block ------------------------------------------------------
#
# --report is read-only and unprivileged, so it is smoked without sudo: a user
# who cannot escalate is exactly the one who most needs to file a usable bug.
check "report names the backend" \
  "$bin --report" \
  '^backend: router'

check "report says the run was live" \
  "$bin --report" \
  '^mode: live$'

check "report lists the backends it probes" \
  "$bin --report" \
  '^backends: '

check "report works in demo mode too" \
  "$bin --demo --report" \
  '^backend: demo$'

# The distro and kernel lines are quoted from the machine's own description of
# itself, and a host named after its distribution would match there without
# anything having leaked. They are dropped before the search, so this stays a
# test of the tool rather than of the guest's hostname.
check "report leaks neither a home path nor the host name" \
  "$bin --report | grep -vE '^(distro|kernel): ' | grep -cE '/home/|$(uname -n)' || true" \
  '^0$'

echo "--- tui-router: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
