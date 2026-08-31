// Command tui-router is the read-only cockpit of the tui-tools family: it
// reads a router's state — interfaces and WAN/LAN roles, the firewall posture,
// live traffic, DHCP leases, WireGuard peers — from cheap system probes, shows
// it as one card per area on a single screen, and hands the terminal to the
// tool that manages each area when you press ENTER on its card.
//
// It changes nothing itself. Every mutation happens in the tool a card
// launches (tui-firewall, tui-network, tui-traffic, tui-vpn), through that
// tool's own preview-and-confirm. The cockpit is the overview and the way in.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/router"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-router/config.toml and ~/.config/tui-router/config.toml.
const toolName = "tui-router"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys the tool understands. Only these
// are read from the environment (TUI_ROUTER_*), so an unrelated variable can
// never leak into the configuration.
func defaults() map[string]string {
	return map[string]string{
		config.KeySudo:  "sudo -n",
		config.KeyTheme: "",
	}
}

// options holds the parsed command line.
type options struct {
	demo        bool
	report      bool
	check       bool
	themePath   string
	sudo        string
	showVersion bool
	// sudoSet records whether -sudo was passed, so `--sudo ""` can disable
	// escalation instead of reading as "not given".
	sudoSet bool
}

// parseFlags defines and reads the command line.
func parseFlags(args []string, out *os.File) (options, error) {
	var opts options
	fs := flag.NewFlagSet(toolName, flag.ContinueOnError)
	fs.SetOutput(out)
	fs.BoolVar(&opts.demo, "demo", false,
		"run against a sample router, without reading or changing anything")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.BoolVar(&opts.check, "check", false,
		"read every card once, print the result as JSON, and exit (no UI)")
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-router — the read-only router cockpit\n\n"+
			"Usage:\n  tui-router [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_ROUTER_* in the environment.\n",
			config.SystemPathFor(toolName), config.UserPathFor(toolName))
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "sudo" {
			opts.sudoSet = true
		}
	})
	return opts, nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, toolName+":", err)
		os.Exit(1)
	}
}

// run wires the configuration, the backend and the Bubble Tea program.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if opts.showVersion {
		fmt.Println(toolName, version)
		return nil
	}

	cfg, err := config.Load(config.Options{Tool: toolName, Defaults: defaults()})
	if err != nil {
		return err
	}
	applyOverrides(&cfg, opts)

	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	// --report is the non-interactive path that must work everywhere: it reads
	// nothing privileged and survives a machine where no backend can be built.
	if opts.report {
		return runReport(cfg, opts, os.Stdout)
	}

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// --check reads every card once and prints JSON. It runs the read path
	// only, so it is safe against a production router.
	if opts.check {
		return runCheck(backend, probeCompat(context.Background(), opts.demo), os.Stdout)
	}

	backends := probeCompat(context.Background(), opts.demo)
	program := tea.NewProgram(newApp(backend, theme.New(), backends),
		tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, the last and
// highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
}

// pickBackend returns the demo backend or the real one.
func pickBackend(cfg config.Config, opts options) (router.Backend, error) {
	if opts.demo {
		return router.NewFake(), nil
	}
	return router.New(cfg.SudoPrefix())
}
