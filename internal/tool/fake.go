package tool

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Fake is the in-memory backend behind --demo and the tests. It builds and
// previews exactly the commands the real backend would, then applies them to
// its own state instead of to the machine.
//
// Every tool in the family has one. It is what makes --demo honest — the UI
// cannot tell it from the real thing — and it is what tests assert against:
// press a key, then check that exactly one command ran, with exactly the argv
// the preview showed.
type Fake struct {
	mu    sync.Mutex
	dir   string
	items []Item
	run   *runner.Fake
}

// NewFake returns a Fake preloaded with a plausible directory.
func NewFake() *Fake {
	f := &Fake{dir: "/srv/demo", items: demoItems()}
	f.run = &runner.Fake{Hook: f.apply}
	return f
}

// Name identifies the backend.
func (f *Fake) Name() string { return "demo" }

// Describe is the one-line summary shown in the header.
func (f *Fake) Describe() string { return f.dir + "  ·  demo (no changes are applied)" }

// Preview renders the command the way the real backend would.
func (f *Fake) Preview(cmd runner.Command) string { return f.run.Preview(cmd) }

// Run applies a confirmed command to the in-memory state.
func (f *Fake) Run(ctx context.Context, cmd runner.Command) (string, error) {
	return f.run.Run(ctx, cmd)
}

// Commands returns every command the fake was asked to run, for the tests.
func (f *Fake) Commands() []runner.Command { return f.run.Ran }

// apply mutates the sample state the way the real command would. It is the
// runner.Fake hook, so it runs only for a command that was previewed and
// confirmed — the same path the real backend takes.
func (f *Fake) apply(cmd runner.Command) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(cmd.Argv) < 2 {
		return "", fmt.Errorf("malformed command %q", cmd)
	}
	name := filepath.Base(cmd.Argv[1])
	for i := range f.items {
		if f.items[i].Name == name {
			f.items[i].Modified = time.Now()
			return "", nil
		}
	}
	return "", fmt.Errorf("touch: cannot touch '%s': No such file or directory", name)
}

// Items returns the sample listing.
func (f *Fake) Items(_ context.Context) ([]Item, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := append([]Item(nil), f.items...)
	SortItems(items)
	return items, nil
}

// Build turns an action into a previewable command, exactly as Real does.
func (f *Fake) Build(spec ActionSpec, name string) (runner.Command, error) {
	if name == "" {
		return runner.Command{}, fmt.Errorf("nothing selected")
	}
	return BuildCommand(spec, filepath.Join(f.dir, name))
}

// demoItems is the sample directory. The times are relative to now, so the
// view reads sensibly however long after this was written it runs.
func demoItems() []Item {
	now := time.Now()
	return []Item{
		{Name: "config", Dir: true, Modified: now.Add(-72 * time.Hour)},
		{Name: "releases", Dir: true, Modified: now.Add(-5 * time.Hour)},
		{Name: "CHANGELOG.md", Size: 4_812, Modified: now.Add(-26 * time.Hour)},
		{Name: "backup.tar.zst", Size: 1_482_119_680, Modified: now.Add(-9 * time.Hour)},
		{Name: "deploy.log", Size: 91_244, Modified: now.Add(-12 * time.Minute)},
		{Name: "notes.txt", Size: 318, Modified: now.Add(-40 * time.Minute)},
		{Name: "server.pem", Size: 1_704, Modified: now.Add(-31 * 24 * time.Hour)},
	}
}
