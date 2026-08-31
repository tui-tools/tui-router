// Command tui-template is the starting point for a new tui-tools tool. It
// lists the files in a directory and can update a file's timestamp, which is
// deliberately trivial: what matters is the shape around it, which is the same
// in every tool of the family.
//
// Rename it, replace internal/tool with your own subject, and keep the
// contract: read-only by default, and no change without a previewed and
// confirmed command line.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/config"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-template/internal/tool"
)

// toolName is the binary name, which is also the configuration directory:
// /etc/tui-template/config.toml and ~/.config/tui-template/config.toml.
const toolName = "tui-template"

// keyDir is this tool's own configuration key. Yours go here.
const keyDir = "dir"

// version is stamped by the release build (-ldflags "-X main.version=…").
var version = "dev"

// defaults declares the configuration keys the tool understands. Only these
// are read from the environment (TUI_TEMPLATE_DIR, …), so an unrelated
// variable can never leak into the configuration.
func defaults() map[string]string {
	return map[string]string{
		keyDir:          ".",
		config.KeySudo:  "sudo -n",
		config.KeyTheme: "",
	}
}

// options holds the parsed command line.
type options struct {
	demo        bool
	report      bool
	dir         string
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
		"run against sample data, without touching anything")
	fs.BoolVar(&opts.report, "report", false, reportUsage)
	fs.StringVar(&opts.dir, "dir", "",
		"directory to list (overrides the config file)")
	fs.StringVar(&opts.themePath, "theme", "",
		"path to an Omarchy-style colors.toml (overrides the config file)")
	fs.StringVar(&opts.sudo, "sudo", "",
		"privilege escalation prefix, e.g. \"sudo -n\" or \"\" to disable")
	fs.BoolVar(&opts.showVersion, "version", false, "print the version and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(out, "tui-template — a starting point for a tui-tools tool\n\n"+
			"Usage:\n  tui-template [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(out, "\nConfiguration is read from %s, then %s, "+
			"then TUI_TEMPLATE_* in the environment.\n",
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

// run wires the configuration, the backend and the Bubble Tea program. Every
// tool in the family has this function, and it is worth keeping it recognisable.
func run(args []string) error {
	opts, err := parseFlags(args, os.Stdout)
	if err != nil {
		// flag already printed the reason and the usage.
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

	// The configured theme is handed to the kit through the same variable the
	// user could set by hand, so precedence stays in one place. It is set
	// before the backend is built so --report can name the theme the UI would
	// have used even on a machine where no backend can be.
	if path := cfg.Theme(); path != "" {
		if err := os.Setenv("TUI_THEME", path); err != nil {
			return err
		}
	}

	// --report is the non-interactive path that must work everywhere. It reads
	// nothing privileged and it survives a machine where no backend can be
	// built, because "there is nothing here to drive" is one of the things a
	// bug report has to be able to say. So it comes before the backend is
	// required.
	if opts.report {
		return runReport(cfg, opts, os.Stdout)
	}

	backend, err := pickBackend(cfg, opts)
	if err != nil {
		return err
	}

	// The backend's version is probed once, at startup, and shown in the
	// header: a version nobody has tested says so there instead of surprising
	// the user later.
	backendCompat := probeCompat(context.Background(), opts.demo)

	program := tea.NewProgram(newApp(backend, theme.New(), backendCompat),
		tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// applyOverrides folds the command line into the configuration, which is the
// last and highest-precedence layer.
func applyOverrides(cfg *config.Config, opts options) {
	if opts.dir != "" {
		cfg.Set(keyDir, opts.dir)
	}
	if opts.themePath != "" {
		cfg.Set(config.KeyTheme, opts.themePath)
	}
	// An explicitly empty -sudo disables escalation, so the flag is applied
	// whenever it was passed, empty value included.
	if opts.sudoSet {
		cfg.Set(config.KeySudo, opts.sudo)
	}
}

// pickBackend returns the demo backend or the real one.
func pickBackend(cfg config.Config, opts options) (tool.Backend, error) {
	if opts.demo {
		return tool.NewFake(), nil
	}
	return tool.New(cfg.String(keyDir, "."), cfg.SudoPrefix())
}
