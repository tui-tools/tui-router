// Package tool is the part of a tui-tools tool that is about its own subject:
// the model it shows, the actions it offers, and the interface a backend
// satisfies. Everything generic — palette, widgets, configuration, running
// commands — comes from tui-kit and is not repeated here.
//
// This is the template's placeholder subject: files in a directory, with one
// action that updates a file's timestamp. It is deliberately trivial and
// deliberately real, so the whole contract is visible end to end. Replace the
// model, the actions and the backends with yours; keep the shape.
package tool

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/tui-tools/tui-kit/runner"
)

// Item is one row of the list. Replace it with whatever your tool shows: a
// firewall rule, a systemd unit, a container.
type Item struct {
	Name string
	// Size is the file size in bytes.
	Size int64
	// Modified is the last modification time.
	Modified time.Time
	// Dir reports whether the entry is a directory.
	Dir bool
}

// SortItems puts the rows in the order the user wants to read them. Every tool
// in the family sorts what matters to the top — failures, then names.
func SortItems(items []Item) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Dir != items[j].Dir {
			return items[i].Dir
		}
		return items[i].Name < items[j].Name
	})
}

// Action is something the user can do to an item.
type Action string

// The actions this template offers. One is enough to show the contract.
const (
	Touch Action = "touch"
)

// ActionSpec describes one action for the key map, the help screen and the
// confirm dialog, so the three cannot drift apart. Add your actions here and
// they appear in all three places at once.
type ActionSpec struct {
	Action Action
	// Key is the key that triggers it.
	Key string
	// Label is the confirm dialog's title.
	Label string
	// Body explains what will happen, above the command preview.
	Body string
	// Destructive paints the dialog in the danger color.
	Destructive bool
}

// Actions is the action table, in help-screen order.
var Actions = []ActionSpec{
	{Action: Touch, Key: "t", Label: "Touch",
		Body: "The file's modification time will be set to now. Its contents are not changed."},
}

// ActionFor returns the spec bound to a key.
func ActionFor(key string) (ActionSpec, bool) {
	for _, spec := range Actions {
		if spec.Key == key {
			return spec, true
		}
	}
	return ActionSpec{}, false
}

// BuildCommand assembles the invocation for an action. It is shared by the
// real and the fake backend, so --demo previews exactly the command the real
// thing would run — which is what makes the demo worth trusting.
func BuildCommand(spec ActionSpec, path string) (runner.Command, error) {
	if spec.Action == "" {
		return runner.Command{}, fmt.Errorf("no action given")
	}
	if path == "" {
		return runner.Command{}, fmt.Errorf("nothing selected")
	}
	return runner.Command{
		Argv:        []string{"touch", path},
		Description: spec.Label + " " + path,
		Destructive: spec.Destructive,
	}, nil
}

// Backend is the boundary between the UI and the machine. The read methods
// return the model; Build turns an intent into a previewable Command; Run
// executes a Command the user confirmed. Nothing else may mutate anything.
type Backend interface {
	// Name identifies the backend ("files", "demo").
	Name() string
	// Describe is the one-line summary shown in the header.
	Describe() string

	// Items reads the current state.
	Items(ctx context.Context) ([]Item, error)

	// Build turns an action on an item into a previewable command.
	Build(spec ActionSpec, name string) (runner.Command, error)
	// Preview renders the exact command line Run will execute.
	Preview(cmd runner.Command) string
	// Run executes a previously previewed command.
	Run(ctx context.Context, cmd runner.Command) (string, error)
}
