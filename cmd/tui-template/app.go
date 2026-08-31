package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/runner"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-template/internal/tool"
)

// mode is the screen the app currently shows. Only one is open at a time,
// which keeps the update loop flat — add your screens here.
type mode int

const (
	modeList mode = iota
	modeConfirm
	modeFilter
	modeHelp
)

// app is the Bubble Tea model.
type app struct {
	backend tool.Backend
	theme   theme.Theme
	// backendCompat is what the version probe found, rendered in the header.
	backendCompat compat.Result

	items   []tool.Item
	visible []tool.Item

	width, height int
	cursor        int
	offset        int
	filter        string

	mode    mode
	confirm ui.Confirm
	input   ui.Input

	status     string
	statusKind ui.StatusKind
	loading    bool
	// loadFailed reports that the last read failed, so the empty state does
	// not claim there is simply nothing to show.
	loadFailed bool
	// busy blocks input while a command runs.
	busy bool
}

// loadedMsg carries the result of a read.
type loadedMsg struct {
	items []tool.Item
	err   error
}

// ranMsg carries the result of a Run.
type ranMsg struct {
	cmd    runner.Command
	output string
	err    error
}

// newApp builds the model around a backend.
func newApp(backend tool.Backend, th theme.Theme,
	backendCompat compat.Result) *app {
	a := &app{backend: backend, theme: th, backendCompat: backendCompat,
		width: 80, height: 24, loading: true}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first read.
func (a *app) Init() tea.Cmd { return a.load() }

// load reads the current state in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		items, err := backend.Items(ctx)
		return loadedMsg{items: items, err: err}
	}
}

// run executes a confirmed command in the background.
func (a *app) run(cmd runner.Command) tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		out, err := backend.Run(ctx, cmd)
		return ranMsg{cmd: cmd, output: out, err: err}
	}
}

// setStatus records a message for the status line.
func (a *app) setStatus(kind ui.StatusKind, message string) {
	a.status = message
	a.statusKind = kind
}

// setStatusf records a formatted message for the status line.
func (a *app) setStatusf(kind ui.StatusKind, format string, args ...any) {
	a.setStatus(kind, fmt.Sprintf(format, args...))
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		a.clampCursor()
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		a.items = msg.items
		a.applyFilter()
		return a, nil

	case ranMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, a.load()
		}
		summary := strings.TrimSpace(msg.output)
		if summary == "" {
			summary = "done"
		}
		a.setStatusf(ui.StatusOK, "%s: %s", msg.cmd.Description,
			runner.FirstLine(summary))
		// Re-read after every change: the system is the source of truth, not
		// what the tool assumed would happen.
		a.loading = true
		return a, a.load()

	case tea.KeyMsg:
		return a.handleKey(msg)
	}

	// Anything else (cursor blink, …) only concerns an open text input.
	if a.mode == modeFilter {
		cmd, _ := a.input.Update(msg)
		return a, cmd
	}
	return a, nil
}

// handleKey routes a key press to the open screen.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// ctrl+c always quits, even mid-dialog.
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		// A command is running: swallow input rather than queueing surprises.
		return a, nil
	}

	switch a.mode {
	case modeConfirm:
		return a.handleConfirm(msg)
	case modeFilter:
		return a.handleFilter(msg)
	case modeHelp:
		a.mode = modeList
		return a, nil
	default:
		return a.handleListKey(msg)
	}
}

// handleConfirm resolves the confirm dialog. This is the only path to a change.
func (a *app) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	a.confirm.Update(msg)
	if !a.confirm.Done {
		return a, nil
	}
	a.mode = modeList
	confirmed := a.confirm.Confirmed
	cmd, ok := a.confirm.Payload.(runner.Command)
	a.confirm = ui.Confirm{}
	if !confirmed || !ok {
		a.setStatus(ui.StatusInfo, "cancelled")
		return a, nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", a.backend.Preview(cmd))
	return a, a.run(cmd)
}

// handleFilter resolves the filter prompt.
func (a *app) handleFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	cmd, _ := a.input.Update(msg)
	if !a.input.Done {
		// Filter as the user types.
		a.filter = a.input.Value()
		a.applyFilter()
		return a, cmd
	}
	if a.input.Accepted {
		a.filter = a.input.Value()
	} else {
		a.filter = ""
	}
	a.applyFilter()
	a.mode = modeList
	return a, nil
}

// handleListKey handles the main screen.
func (a *app) handleListKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// An action key applies to the selection and always opens a confirm
	// dialog first, so the action table is the single source of truth for
	// what each key does.
	if spec, ok := tool.ActionFor(key); ok {
		return a, a.confirmAction(spec)
	}

	switch key {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down":
		a.moveCursor(1)
	case "k", "up":
		a.moveCursor(-1)
	case "g", "home":
		a.cursor, a.offset = 0, 0
	case "G", "end":
		a.cursor = max(len(a.visible)-1, 0)
		a.clampCursor()
	case "pgdown", "ctrl+f":
		a.moveCursor(a.listHeight())
	case "pgup", "ctrl+b":
		a.moveCursor(-a.listHeight())
	case "/":
		a.input = ui.NewInput("Filter", "name…", a.filter)
		a.input.Help = "Empty clears the filter."
		a.mode = modeFilter
	case "r", "ctrl+r":
		a.loading = true
		return a, a.load()
	}
	return a, nil
}

// confirmAction builds an action's command and opens the confirm dialog.
func (a *app) confirmAction(spec tool.ActionSpec) tea.Cmd {
	item, ok := a.selected()
	if !ok {
		a.setStatus(ui.StatusWarn, "nothing selected")
		return nil
	}
	cmd, err := a.backend.Build(spec, item.Name)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.mode = modeConfirm
	a.confirm = ui.Confirm{
		Title:   cmd.Description,
		Body:    spec.Body,
		Command: a.backend.Preview(cmd),
		Danger:  cmd.Destructive,
		Payload: cmd,
	}
	return nil
}

// applyFilter recomputes the visible rows.
func (a *app) applyFilter() {
	if a.filter == "" {
		a.visible = a.items
		a.clampCursor()
		return
	}
	needle := strings.ToLower(a.filter)
	kept := make([]tool.Item, 0, len(a.items))
	for _, item := range a.items {
		if strings.Contains(strings.ToLower(item.Name), needle) {
			kept = append(kept, item)
		}
	}
	a.visible = kept
	a.clampCursor()
}

// selected returns the highlighted row.
func (a *app) selected() (tool.Item, bool) {
	if a.cursor < 0 || a.cursor >= len(a.visible) {
		return tool.Item{}, false
	}
	return a.visible[a.cursor], true
}

// moveCursor moves the selection and keeps the viewport in sync.
func (a *app) moveCursor(delta int) {
	a.cursor += delta
	a.clampCursor()
}

// clampCursor keeps the cursor and the scroll offset within range.
func (a *app) clampCursor() {
	if len(a.visible) == 0 {
		a.cursor, a.offset = 0, 0
		return
	}
	a.cursor = min(max(a.cursor, 0), len(a.visible)-1)

	height := a.listHeight()
	if a.cursor < a.offset {
		a.offset = a.cursor
	}
	if a.cursor >= a.offset+height {
		a.offset = a.cursor - height + 1
	}
	a.offset = max(min(a.offset, max(len(a.visible)-height, 0)), 0)
}
