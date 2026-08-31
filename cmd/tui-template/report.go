package main

import (
	"context"
	"fmt"
	"io"
	"regexp"

	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
)

// listerName is what the real backend calls itself (tool.Real.Name()). It is
// not what the manifest calls the program that backend drives — coreutils —
// and most tools have one name for both.
const listerName = "files"

// runReport prints the block a bug report needs and exits. Every tool in the
// family has this function, and it is worth keeping it recognisable.
//
// Everything generic — the kit version, the distribution, the kernel, the
// terminal, where the binary came from — is collected by the kit, so the whole
// family answers --report in the same shape. What a tool adds is the part only
// it knows: here, the version the compat probe read off coreutils, and the
// backend the fake imitates when --demo is on. Yours will add the backend it
// selected and what it saw of the ones it did not.
//
// Two rules make it worth copying. It reads nothing privileged, because a user
// who cannot escalate is the one who most needs to be able to file a usable
// bug. And it runs before the backend is built, so a machine where no backend
// can be selected at all still produces a report, with the failure as one of
// its lines: "there is nothing here to drive" is a bug report, not a refusal.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()

	// The same probe the header uses. There is one version probe in a tool and
	// this is it — a report that probed separately could disagree with the
	// header the user is looking at.
	backendCompat := probeCompat(context.Background(), opts.demo)

	var backendError string
	if _, err := pickBackend(cfg, opts); err != nil {
		backendError = err.Error()
	}

	info := report.Info{
		Tool:           toolName,
		Version:        version,
		Backend:        backendName,
		BackendVersion: backendCompat.Version,
		BackendDetail:  backendCompat.Detail,
		Demo:           opts.demo,
		Sudo:           cfg.String(config.KeySudo, ""),
		Theme:          palette.Name,
	}
	if opts.demo {
		// The fake imitates the real backend, and which one it imitates
		// decides which command builders and which parser the session
		// exercised. A fake is free to call itself "demo" — this one does —
		// so the imitated backend is named here rather than asked of the fake.
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: listerName,
		})
	}
	if backendError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: scrubHome(backendError),
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// homePath matches a path under a home directory, which is the one thing this
// tool could otherwise put in the block that names its user: the directory it
// lists is configuration, and a failure to open it says so with the path in it.
var homePath = regexp.MustCompile(`(/home|/root)(/[^\s:]*)?`)

// scrubHome replaces such a path with the placeholder the kit uses for the
// same reason. The block is pasted into a public issue, so a value a tool hands
// to report.Extra is its own responsibility: the kit scrubs what it collected
// itself and cannot know what is inside a message a tool passes on.
//
// Every tool has at least one of these. It is worth finding it before a user
// does: run --report on a machine where the backend is missing, and read what
// comes out.
func scrubHome(s string) string {
	return homePath.ReplaceAllString(s, "~elsewhere~")
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
