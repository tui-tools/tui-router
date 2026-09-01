package main

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/tui-tools/tui-kit/compat"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-router/internal/router"
)

// refreshInterval is how often the cockpit re-reads the machine, so the
// traffic card shows a live number rather than a stale one.
const refreshInterval = 2 * time.Second

// mode is the screen the app currently shows.
type mode int

const (
	modeCockpit mode = iota
	modeHelp
)

// app is the Bubble Tea model.
type app struct {
	backend  router.Backend
	theme    theme.Theme
	backends []compat.Result

	cards []router.Card
	// prev and cur are the last two snapshots; the traffic card is the delta
	// between them.
	prev *router.Snapshot
	cur  *router.Snapshot

	width, height int
	cursor        int

	mode       mode
	status     string
	statusKind ui.StatusKind
	loading    bool
	loadFailed bool
	// busy blocks input and the refresh tick while a handoff is running.
	busy bool

	// wiz is the roles wizard while it is open; the cockpit's one guided
	// mutation (see wizard.go).
	wiz *wizard
	// power is the typed reboot/poweroff confirm while it is open.
	power *powerDialog
	// bak is the backup screen while it is open (see backupscreen.go).
	bak *backupScreen
}

// loadedMsg carries the result of a read.
type loadedMsg struct {
	snap router.Snapshot
	err  error
}

// launchedMsg carries the result of handing the terminal to another tool.
type launchedMsg struct {
	name string
	err  error
}

// tickMsg fires the periodic refresh.
type tickMsg struct{}

// newApp builds the model around a backend.
func newApp(backend router.Backend, th theme.Theme, backends []compat.Result) *app {
	a := &app{backend: backend, theme: th, backends: backends,
		width: 80, height: 24, loading: true}
	if th.Warning != "" {
		a.setStatus(ui.StatusWarn, th.Warning)
	}
	return a
}

// Init starts the first read and the refresh tick.
func (a *app) Init() tea.Cmd { return tea.Batch(a.load(), tick()) }

// load reads a snapshot in the background.
func (a *app) load() tea.Cmd {
	backend := a.backend
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		snap, err := backend.Read(ctx)
		return loadedMsg{snap: snap, err: err}
	}
}

// tick schedules the next refresh.
func tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(time.Time) tea.Msg { return tickMsg{} })
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

// rebuild recomputes the cards from the last two snapshots.
func (a *app) rebuild() {
	if a.cur == nil {
		return
	}
	a.cards = router.Cards(*a.cur, a.prev, a.backend.ToolInstalled)
	if a.cursor >= len(a.cards) {
		a.cursor = len(a.cards) - 1
	}
	if a.cursor < 0 {
		a.cursor = 0
	}
}

// Update is the main event loop.
func (a *app) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// While the wizard is open it owns every message except the window size
	// and the clock; the refresh is paused so the roles state the wizard is
	// editing cannot change under it.
	if a.wiz != nil {
		switch msg.(type) {
		case tea.WindowSizeMsg:
			// Falls through to the normal handling below.
		case tickMsg:
			return a, tick()
		case loadedMsg:
			return a, nil
		default:
			cmd := a.wiz.Update(msg)
			if a.wiz.closed {
				a.wiz = nil
				// The wizard may have changed the machine — re-read it.
				a.loading = true
				return a, tea.Batch(cmd, a.load())
			}
			return a, cmd
		}
	}
	// The backup screen owns its keys the same way the wizard does, and for
	// the same reason: it is walking the operator through a mutation, and a
	// refresh under it would change the machine it is diffing against. Its
	// own async results still have to reach it, so they fall through to its
	// Update rather than the cockpit's.
	if a.bak != nil {
		switch msg.(type) {
		case tea.WindowSizeMsg:
			// Falls through to the normal handling below.
		case tickMsg:
			return a, tick()
		case loadedMsg:
			return a, nil
		default:
			cmd := a.bak.Update(msg)
			if a.bak.closed {
				a.bak = nil
				// A restore may have changed the machine — re-read it.
				a.loading = true
				return a, tea.Batch(cmd, a.load())
			}
			return a, cmd
		}
	}
	// The typed power confirm likewise owns the keys while it is open.
	if a.power != nil {
		switch msg.(type) {
		case tea.WindowSizeMsg, tickMsg, loadedMsg, powerDoneMsg:
			// Falls through to the normal handling below.
		default:
			cmd := a.power.Update(msg)
			if a.power.done {
				dialog := a.power
				a.power = nil
				if dialog.confirmed {
					a.busy = true
					a.setStatusf(ui.StatusInfo, "running %s…", dialog.action.word)
					return a, tea.Batch(cmd, runPower(dialog.action))
				}
				a.setStatusf(ui.StatusInfo, "%s cancelled", dialog.action.word)
			}
			return a, cmd
		}
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		return a, nil

	case loadedMsg:
		a.loading = false
		if msg.err != nil {
			a.loadFailed = true
			a.setStatus(ui.StatusError, msg.err.Error())
			return a, nil
		}
		a.loadFailed = false
		// Keep the previous snapshot so the traffic card has two points in
		// time to derive a rate from.
		a.prev = a.cur
		snap := msg.snap
		a.cur = &snap
		a.rebuild()
		return a, nil

	case tickMsg:
		if a.busy {
			return a, tick()
		}
		return a, tea.Batch(a.load(), tick())

	case launchedMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatusf(ui.StatusError, "%s: %v", msg.name, msg.err)
			return a, nil
		}
		a.setStatusf(ui.StatusInfo, "%s exited", msg.name)
		// The tool we handed off to may have changed the machine — the
		// cockpit shows the machine, not what it remembered of it.
		a.loading = true
		return a, a.load()

	case powerDoneMsg:
		a.busy = false
		if msg.err != nil {
			a.setStatusf(ui.StatusError, "%s: %v", msg.word, msg.err)
			return a, nil
		}
		a.setStatusf(ui.StatusInfo, "%s requested", msg.word)
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(msg)
	}
	return a, nil
}

// handleKey routes a key press.
func (a *app) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	if a.busy {
		return a, nil
	}
	if a.mode == modeHelp {
		a.mode = modeCockpit
		return a, nil
	}

	switch msg.String() {
	case "q", "esc":
		return a, tea.Quit
	case "?":
		a.mode = modeHelp
	case "j", "down", "tab":
		a.moveCursor(1)
	case "k", "up", "shift+tab":
		a.moveCursor(-1)
	case "g", "home":
		a.cursor = 0
	case "G", "end":
		a.cursor = max(len(a.cards)-1, 0)
	case "r", "ctrl+r":
		a.loading = true
		return a, a.load()
	case "enter":
		return a, a.launch()
	case "w":
		a.openWizard()
	case "b":
		a.openBackup()
	case "B":
		a.openPower("reboot")
	case "P":
		a.openPower("poweroff")
	}
	return a, nil
}

// openBackup opens the backup screen when the backend can export and restore.
func (a *app) openBackup() {
	backend, ok := a.backend.(router.BackupBackend)
	if !ok {
		a.setStatus(ui.StatusWarn, "this backend cannot export or restore")
		return
	}
	a.bak = newBackupScreen(backend)
}

// openWizard opens the roles wizard when this is a router-profile host and
// the backend can manage roles.
func (a *app) openWizard() {
	if a.cur == nil {
		return
	}
	mgr, ok := a.backend.(router.RoleManager)
	if !ok {
		a.setStatus(ui.StatusWarn, "this backend cannot manage roles")
		return
	}
	if !a.cur.Roles.ProfilePresent {
		a.setStatus(ui.StatusWarn,
			"no router profile here ("+router.RolesDir+" is absent) — nothing to assign")
		return
	}
	a.wiz = newWizard(mgr, a.cur.Roles, a.cur.Interfaces)
}

// openPower opens the typed confirm for one power action.
func (a *app) openPower(word string) {
	pm, ok := a.backend.(router.PowerManager)
	if !ok {
		a.setStatus(ui.StatusWarn, "this backend cannot manage power")
		return
	}
	var action powerAction
	switch word {
	case "reboot":
		action = powerAction{word: "reboot", preview: pm.RebootPreview(), exec: pm.Reboot}
	case "poweroff":
		action = powerAction{word: "poweroff", preview: pm.PoweroffPreview(), exec: pm.Poweroff}
	default:
		return
	}
	a.power = newPowerDialog(action)
}

// launch hands the terminal to the selected card's managing tool, when it is
// installed. When it is not, it says so and offers nothing destructive.
func (a *app) launch() tea.Cmd {
	card, ok := a.selected()
	if !ok {
		return nil
	}
	if !card.ToolInstalled {
		a.setStatusf(ui.StatusWarn, "%s is not installed — it manages the %s card",
			card.Tool, card.Title)
		return nil
	}
	process, err := a.backend.Launch(card.Tool)
	if err != nil {
		a.setStatus(ui.StatusError, err.Error())
		return nil
	}
	a.busy = true
	a.setStatusf(ui.StatusInfo, "running %s…", card.Tool)
	name := card.Tool
	return tea.Exec(process, func(err error) tea.Msg {
		return launchedMsg{name: name, err: err}
	})
}

// selected returns the highlighted card.
func (a *app) selected() (router.Card, bool) {
	if a.cursor < 0 || a.cursor >= len(a.cards) {
		return router.Card{}, false
	}
	return a.cards[a.cursor], true
}

// moveCursor moves the selection between cards.
func (a *app) moveCursor(delta int) {
	if len(a.cards) == 0 {
		return
	}
	a.cursor = (a.cursor + delta + len(a.cards)) % len(a.cards)
}
