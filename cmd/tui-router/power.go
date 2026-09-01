// The cockpit's power keys. Rebooting or powering off a router is the one
// mutation heavier than anything a card's tool does, so it sits behind a
// typed confirm: the dialog previews the exact systemctl command and runs it
// only when the operator types the action's own name.
package main

import (
	"context"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-kit/ui"
)

// powerAction is one previewed power command.
type powerAction struct {
	// word is both the action's name and the text the operator must type.
	word    string
	preview string
	exec    func(ctx context.Context) error
}

// powerDialog is the typed confirm around one power action.
type powerDialog struct {
	action powerAction
	input  ui.Input
	// done and confirmed report the outcome once the dialog closes.
	done      bool
	confirmed bool
}

// newPowerDialog builds the dialog for one action.
func newPowerDialog(action powerAction) *powerDialog {
	return &powerDialog{
		action: action,
		input:  ui.NewInput("", action.word, ""),
	}
}

// Update forwards a message to the text input. When the input resolves, the
// dialog is confirmed only if the typed word matches the action exactly.
func (p *powerDialog) Update(msg tea.Msg) tea.Cmd {
	cmd, _ := p.input.Update(msg)
	if p.input.Done {
		p.done = true
		p.confirmed = p.input.Accepted &&
			strings.TrimSpace(p.input.Value()) == p.action.word
	}
	return cmd
}

// View renders the danger dialog: what is about to happen, the exact command,
// and the typed prompt.
func (p *powerDialog) View(t theme.Theme, width, height int) string {
	lines := []string{
		t.Danger.Render(strings.ToUpper(p.action.word[:1]) + p.action.word[1:] + " this router?"),
		"",
		t.Base.Render("This affects the whole machine — every client behind it loses"),
		t.Base.Render("connectivity until it is back."),
		"",
		t.Muted.Render("Command to run:"),
		t.Command.Render("$ " + p.action.preview),
		"",
		t.Base.Render("Type \"" + p.action.word + "\" and press enter to confirm:"),
		p.input.Model.View(),
		"",
		t.Key.Render("enter") + t.KeyDesc.Render(" confirm    ") +
			t.Key.Render("esc") + t.KeyDesc.Render(" cancel"),
	}
	box := t.Dialog.MaxWidth(max(width-4, 20)).Render(strings.Join(lines, "\n"))
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

// powerDoneMsg reports the outcome of running a power action.
type powerDoneMsg struct {
	word string
	err  error
}

// runPower executes a confirmed power action in the background.
func runPower(action powerAction) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return powerDoneMsg{word: action.word, err: action.exec(ctx)}
	}
}
