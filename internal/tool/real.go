package tool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tui-tools/tui-kit/runner"
)

// Real is the backend that touches the machine. Yours will read a command's
// output instead of a directory; the shape stays the same.
type Real struct {
	dir string
	run *runner.Runner
}

// New builds the real backend. sudoPrefix comes from the configuration
// ("sudo -n"); pass nil to run the command directly.
//
// Resolving the binary, applying the privilege prefix, bounding each call and
// turning a failure into one readable line all belong to the kit runner. A
// tool that cannot escalate finds out here, at startup, rather than halfway
// through a change.
func New(dir string, sudoPrefix []string) (*Real, error) {
	if dir == "" {
		dir = "."
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if info, err := os.Stat(absolute); err != nil || !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", absolute)
	}
	r, err := runner.New(runner.Options{
		Bin:         "touch",
		SearchPaths: []string{"/usr/bin/touch", "/bin/touch"},
		SudoPrefix:  sudoPrefix,
		// Reads here are a directory listing, not a command, so escalation
		// never applies to them. A tool whose reads need root (ufw status)
		// leaves this at its default.
		PrivilegedReads: &unprivileged,
		InstallHint:     "it comes with coreutils",
	})
	if err != nil {
		return nil, err
	}
	return &Real{dir: absolute, run: r}, nil
}

// unprivileged is the address-of-false the runner options need.
var unprivileged = false

// Name identifies the backend.
func (r *Real) Name() string { return "files" }

// Describe is the one-line summary shown in the header.
func (r *Real) Describe() string { return r.dir }

// Dir is the directory being listed.
func (r *Real) Dir() string { return r.dir }

// Preview renders the exact command line Run will execute.
func (r *Real) Preview(cmd runner.Command) string { return r.run.Preview(cmd) }

// Run executes a previewed command.
func (r *Real) Run(ctx context.Context, cmd runner.Command) (string, error) {
	return r.run.Run(ctx, cmd)
}

// Items reads the directory.
func (r *Real) Items(_ context.Context) ([]Item, error) {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", r.dir, err)
	}
	items := make([]Item, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			// An entry that vanished between the listing and the stat is not
			// an error worth failing the whole read for.
			continue
		}
		items = append(items, Item{
			Name: entry.Name(), Size: info.Size(),
			Modified: info.ModTime(), Dir: entry.IsDir(),
		})
	}
	SortItems(items)
	return items, nil
}

// Build turns an action into a previewable command, resolving the item name
// against the directory being listed.
func (r *Real) Build(spec ActionSpec, name string) (runner.Command, error) {
	if name == "" {
		return runner.Command{}, fmt.Errorf("nothing selected")
	}
	return BuildCommand(spec, filepath.Join(r.dir, name))
}
