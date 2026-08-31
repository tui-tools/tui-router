package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-template/internal/tool"
)

// Layout constants: the rows the list cannot use.
const (
	headerLines = 2
	footerLines = 2
	// minListHeight keeps at least one visible row on a very short terminal.
	minListHeight = 1
)

// listHeight is the number of rows that fit on screen.
func (a *app) listHeight() int {
	// header + table header + help bar + status line.
	return max(a.height-headerLines-footerLines-2, minListHeight)
}

// View renders the whole screen.
func (a *app) View() string {
	switch a.mode {
	case modeConfirm:
		return a.confirm.View(a.theme, a.width, a.height)
	case modeFilter:
		return a.input.View(a.theme, a.width, a.height)
	case modeHelp:
		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center,
			ui.HelpScreen(a.theme, "tui-template — keys", helpKeys(), a.width))
	default:
		return a.listView()
	}
}

// listView renders the main screen: header, table, help bar, status line. Every
// tool in the family draws these same four bands.
func (a *app) listView() string {
	var body string
	switch {
	case a.loading && len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "reading…", a.width, a.listHeight()+1)
	case len(a.visible) == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme, "could not read — see the message below",
			a.width, a.listHeight()+1)
	case len(a.visible) == 0 && a.filter != "":
		body = ui.EmptyState(a.theme, "nothing matches "+strconv.Quote(a.filter),
			a.width, a.listHeight()+1)
	case len(a.visible) == 0:
		body = ui.EmptyState(a.theme, "nothing here", a.width, a.listHeight()+1)
	default:
		body = a.table()
	}

	help := ui.HelpBar(a.theme, shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	return strings.Join([]string{a.header(), body, help, status}, "\n")
}

// header renders the facts at the top of the screen.
func (a *app) header() string {
	dirs := 0
	for _, item := range a.items {
		if item.Dir {
			dirs++
		}
	}
	facts := []ui.Fact{
		{Label: "entries", Value: strconv.Itoa(len(a.items))},
		{Label: "directories", Value: strconv.Itoa(dirs)},
	}
	// The backend version, when it was probed: quiet on a tested version,
	// coloured on one nobody has run against. Keep this in your tool.
	if a.backendCompat.Backend != "" {
		facts = append(facts, ui.CompatFact(a.theme, a.backendCompat))
	}
	subtitle := a.backend.Describe()
	if a.filter != "" {
		subtitle += "  ·  filter: " + a.filter
	}
	return ui.Header{Title: "tui-template", Subtitle: subtitle, Facts: facts}.
		Render(a.theme, a.width)
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	count := strconv.Itoa(len(a.visible))
	if len(a.visible) != len(a.items) {
		return count + " of " + strconv.Itoa(len(a.items)) + " entries  ·  ? for help"
	}
	return count + " entries  ·  ? for help"
}

// table renders the list, dropping columns on narrow terminals.
func (a *app) table() string {
	columns := []ui.Column{
		{Title: "NAME", Width: 24, Flex: true},
		{Title: "SIZE", Width: 10},
	}
	showModified := a.width >= 60
	if showModified {
		columns = append(columns, ui.Column{Title: "MODIFIED", Width: 12})
	}

	now := time.Now()
	rows := make([][]string, 0, len(a.visible))
	styles := make([]*lipgloss.Style, 0, len(a.visible))
	for _, item := range a.visible {
		row := []string{item.Name, size(item)}
		if showModified {
			row = append(row, ago(now, item.Modified))
		}
		rows = append(rows, row)
		styles = append(styles, a.itemStyle(item))
	}

	return ui.Table{
		Columns: columns, Rows: rows, Styles: styles,
		Selected: a.cursor, Offset: a.offset, Height: a.listHeight(),
	}.Render(a.theme, a.width)
}

// itemStyle colors a row, so the eye finds what matters without reading.
func (a *app) itemStyle(item tool.Item) *lipgloss.Style {
	var style lipgloss.Style
	if item.Dir {
		style = a.theme.Row.Foreground(a.theme.Info.GetForeground())
	} else {
		style = a.theme.Row
	}
	return &style
}

// size renders a byte count in the largest unit that keeps it short.
func size(item tool.Item) string {
	if item.Dir {
		return "-"
	}
	const unit = 1024
	if item.Size < unit {
		return fmt.Sprintf("%dB", item.Size)
	}
	div, exp := int64(unit), 0
	for n := item.Size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(item.Size)/float64(div), "KMGTPE"[exp])
}

// ago renders how long ago a moment was, in one unit.
func ago(now, t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dmin ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// shortHelpKeys is the single-line hint bar.
func shortHelpKeys() []ui.KeyHint {
	hints := make([]ui.KeyHint, 0, len(tool.Actions)+4)
	for _, spec := range tool.Actions {
		hints = append(hints, ui.KeyHint{
			Key: spec.Key, Desc: strings.ToLower(spec.Label)})
	}
	return append(hints,
		ui.KeyHint{Key: "/", Desc: "filter"},
		ui.KeyHint{Key: "r", Desc: "re-read"},
		ui.KeyHint{Key: "?", Desc: "help"},
		ui.KeyHint{Key: "q", Desc: "quit"},
	)
}

// helpKeys is the full key list. The action rows are generated from the action
// table, so a new action cannot be missing from the help.
func helpKeys() []ui.KeyHint {
	hints := []ui.KeyHint{
		{Key: "↑/k, ↓/j", Desc: "move the selection"},
		{Key: "g / G", Desc: "first / last row"},
		{Key: "pgup/pgdn", Desc: "scroll a page"},
		{Key: "/", Desc: "filter by name (esc clears)"},
		{Key: "", Desc: ""},
	}
	for _, spec := range tool.Actions {
		hints = append(hints, ui.KeyHint{
			Key: spec.Key, Desc: strings.ToLower(spec.Label) + " the selected entry"})
	}
	return append(hints,
		ui.KeyHint{Key: "", Desc: ""},
		ui.KeyHint{Key: "r", Desc: "re-read"},
		ui.KeyHint{Key: "?", Desc: "this help"},
		ui.KeyHint{Key: "q", Desc: "quit"},
		ui.KeyHint{Key: "", Desc: ""},
		ui.KeyHint{Key: "note", Desc: "every change is previewed and confirmed first"},
	)
}
