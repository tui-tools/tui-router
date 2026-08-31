# Contributing

Thanks for looking. This is an early project, so the most useful contributions
right now are bug reports from real machines: which distribution, which version
of the tool it drives, and what the tool showed you.

## Before you open a pull request

- Open an issue first for anything larger than a fix. It saves you writing code
  against a design that was about to change.
- `make check` must pass: gofmt, `go vet` and the tests. That is exactly what CI
  runs.
- Add a test for parsing changes. Every parser in the family is table-driven
  against real command output — paste the output you saw into a new case.

## House rules

These are not style preferences, they are what makes the family coherent.

- **Preview, then confirm.** Nothing may change the system without first showing
  the exact command line. Build a `runner.Command`, show it, run that same
  value. If a change needs a new path to a mutation, it needs a discussion.
- **Read-only by default.** Starting a tool only reads state.
- **No daemon, no state of its own.** The system is the source of truth; re-read
  it after every change.
- **English everywhere**: code, comments, commit messages, UI strings.
- **Small dependencies.** Bubble Tea, Bubbles, Lip Gloss and the kit. Adding a
  fourth needs a reason.
- Commit messages say *why*, in the imperative: `Parse ufw route rules`, not
  `fixed stuff`.

## Layout

Shared code — palette, widgets, config, the command runner — lives in
[tui-kit](https://github.com/tui-tools/tui-kit) and is used by every tool. If
your change would help a second tool, it probably belongs there.

## Releases

Maintainers tag `vX.Y.Z` on `main`; CI builds the static linux/amd64 and
linux/arm64 binaries and attaches them to the release.
