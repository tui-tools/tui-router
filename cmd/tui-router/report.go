package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/report"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/router"
)

// notAvailable is the runner's own wording for a program this machine does not
// have. It separates "wireguard-tools is absent" from "it is here and the
// probe could not read a version off it" on the backends line.
const notAvailable = "command not available"

// noVersionDetail is why the backend line carries no version: the cockpit's
// backend is the machine itself, which has no single version to read. The
// programs it probes each have one, on the backends line below.
const noVersionDetail = "the machine itself, so there is no one version to read"

// runReport prints the block a bug report needs and exits. Everything generic
// — the kit version, the distribution, the kernel, the terminal, where the
// binary came from — is collected by the kit, so the whole family answers
// --report in the same shape. What the cockpit adds is the version of every
// program it reads, and which of them this machine does not have.
//
// It never runs a card read. --check is the flag that does that; a report has
// to work for a user who cannot escalate, because the missing privilege may be
// the bug. The only commands it runs are the version probes the header uses.
func runReport(cfg config.Config, opts options, out io.Writer) error {
	palette, _ := theme.ResolvePalette()
	backends := probeCompat(context.Background(), opts.demo)

	var backendName, selectError string
	if backend, err := pickBackend(cfg, opts); err != nil {
		selectError = err.Error()
	} else {
		backendName = backend.Name()
	}

	info := report.Info{
		Tool:          toolName,
		Version:       version,
		Backend:       backendName,
		BackendDetail: noVersionDetail,
		Demo:          opts.demo,
		Sudo:          cfg.String(config.KeySudo, ""),
		Theme:         palette.Name,
	}
	if opts.demo {
		info.Backend = "demo"
		info.Extra = append(info.Extra, report.Field{
			Key: "demo backend", Value: "router",
		})
	} else {
		info.Extra = append(info.Extra, report.Field{
			Key: "backends", Value: describeBackends(backends),
		})
		info.Extra = append(info.Extra, report.Field{
			Key: "managing tools", Value: describeTools(),
		})
	}
	if selectError != "" {
		info.Extra = append(info.Extra, report.Field{
			Key: "backend error", Value: selectError,
		})
	}

	_, err := io.WriteString(out, report.Render(info))
	return err
}

// describeBackends renders every backend the tool probes as one line: the
// version where there is one, "absent" where the program is not here.
func describeBackends(results []compat.Result) string {
	parts := make([]string, 0, len(results))
	for _, result := range results {
		name := strings.TrimSpace(result.Backend)
		if name == "" {
			continue
		}
		switch {
		case result.Version != "":
			parts = append(parts, name+" "+result.Version)
		case strings.Contains(result.Detail, notAvailable):
			parts = append(parts, name+" absent")
		default:
			parts = append(parts, name+" (version unread)")
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// describeTools reports which managing tools are installed, since a handoff
// that does nothing is usually a tool that is not on the machine. It reads a
// PATH lookup and nothing about the user.
func describeTools() string {
	seen := map[string]bool{}
	var parts []string
	for _, kind := range []string{"tui-network", "tui-firewall", "tui-traffic", "tui-vpn"} {
		if seen[kind] {
			continue
		}
		seen[kind] = true
		state := "absent"
		if router.OnPath(kind) {
			state = "present"
		}
		parts = append(parts, kind+" "+state)
	}
	return strings.Join(parts, ", ")
}

// reportUsage is the flag's one-line help, kept here next to what it prints.
var reportUsage = fmt.Sprintf(
	"print the versions and machine facts a bug report needs, then exit "+
		"(no UI, no privileges, nothing about you: paste it into a %s issue)",
	toolName)
