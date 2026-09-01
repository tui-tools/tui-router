package main

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/ui"
	"github.com/tui-tools/tui-router/internal/router"
)

// Layout constants: the rows the card grid cannot use.
const (
	headerLines = 2
	footerLines = 2
	// cardGap is the space between two cards in a row.
	cardGap = 1
	// minCardWidth is the narrowest a card is allowed to be before the grid
	// drops to a single column.
	minCardWidth = 34
)

// View renders the whole screen.
func (a *app) View() string {
	if a.wiz != nil {
		return a.wiz.View(a.theme, a.width, a.height)
	}
	if a.power != nil {
		return a.power.View(a.theme, a.width, a.height)
	}
	if a.bak != nil {
		return a.bak.View(a.theme, a.width, a.height)
	}
	if a.mode == modeHelp {
		return lipgloss.Place(a.width, a.height, lipgloss.Center, lipgloss.Center,
			ui.HelpScreen(a.theme, "tui-router — keys", helpKeys(), a.width))
	}

	var body string
	switch {
	case a.loading && len(a.cards) == 0:
		body = ui.EmptyState(a.theme, "reading the router…", a.width, a.bodyHeight())
	case len(a.cards) == 0 && a.loadFailed:
		body = ui.EmptyState(a.theme, "could not read — see the message below",
			a.width, a.bodyHeight())
	case len(a.cards) == 0:
		body = ui.EmptyState(a.theme, "nothing to show", a.width, a.bodyHeight())
	default:
		body = a.grid()
	}

	help := ui.HelpBar(a.theme, shortHelpKeys(), a.width)
	status := ui.StatusLine(a.theme, a.statusKind, a.status, a.defaultStatus(), a.width)
	parts := []string{a.header()}
	if banner := a.rolesBanner(); banner != "" {
		parts = append(parts, banner)
	}
	parts = append(parts, body, help, status)
	return strings.Join(parts, "\n")
}

// rolesBanner is the safe-mode warning: a router-profile host whose WAN/LAN
// roles are not both assigned forwards nothing, and the wizard fixes that.
func (a *app) rolesBanner() string {
	if a.cur == nil || !a.cur.Roles.NeedsWizard() {
		return ""
	}
	text := "▲ WAN/LAN roles not assigned — safe mode, nothing is forwarded." +
		"  Press w for the roles wizard."
	return a.theme.Warn.Render(ui.Truncate(text, a.width))
}

// bannerLines is how many rows the roles banner takes.
func (a *app) bannerLines() int {
	if a.rolesBanner() == "" {
		return 0
	}
	return 1
}

// bodyHeight is the number of rows the card grid may use: the screen less the
// two-line header, the banner when it shows, the help bar and the status line.
func (a *app) bodyHeight() int {
	return max(a.height-headerLines-a.bannerLines()-2, 6)
}

// header renders the facts at the top of the screen.
func (a *app) header() string {
	facts := a.summaryFacts()
	for _, result := range installed(a.backends) {
		facts = append(facts, ui.CompatFact(a.theme, result))
	}
	subtitle := a.backend.Describe()
	return ui.Header{Title: "tui-router", Subtitle: subtitle, Facts: facts}.
		Render(a.theme, a.width)
}

// summaryFacts is the one-glance line: how many cards are healthy, and how many
// managing tools are actually installed.
func (a *app) summaryFacts() []ui.Fact {
	ok, warn, unknown, tools := 0, 0, 0, 0
	for _, card := range a.cards {
		switch card.Status {
		case router.StatusOK:
			ok++
		case router.StatusWarn:
			warn++
		case router.StatusUnknown:
			unknown++
		}
		if card.ToolInstalled {
			tools++
		}
	}
	value := strconv.Itoa(ok) + " ok"
	if warn > 0 {
		value += " · " + strconv.Itoa(warn) + " warn"
	}
	if unknown > 0 {
		value += " · " + strconv.Itoa(unknown) + " unknown"
	}
	return []ui.Fact{
		{Label: "cards", Value: value},
		{Label: "tools", Value: strconv.Itoa(tools) + " of " + strconv.Itoa(len(a.cards)) + " installed"},
	}
}

// defaultStatus is the hint shown when there is no message to report.
func (a *app) defaultStatus() string {
	if card, ok := a.selected(); ok {
		if card.ToolInstalled {
			return "enter opens " + card.Tool + "  ·  ? for help"
		}
		return card.Tool + " not installed  ·  ? for help"
	}
	return "? for help"
}

// grid lays the cards out in as many columns as the width allows, then stacks
// the rows to fill the body.
func (a *app) grid() string {
	columns := a.width / (minCardWidth + cardGap)
	if columns < 1 {
		columns = 1
	}
	if columns > len(a.cards) {
		columns = len(a.cards)
	}
	cardWidth := (a.width - (columns-1)*cardGap) / columns

	// Fit the grid to the body: each card's interior is the height left over
	// once the rows share the space, so the header above always shows and a
	// card with more detail than fits ends in an ellipsis rather than pushing
	// the top of the screen off.
	rowsCount := (len(a.cards) + columns - 1) / columns
	interior := 3
	if rowsCount > 0 {
		interior = max((a.bodyHeight()-rowsCount*2)/rowsCount, 3)
	}

	boxes := make([]string, len(a.cards))
	for i, card := range a.cards {
		boxes[i] = a.card(card, i == a.cursor, cardWidth, interior)
	}

	var rows []string
	for i := 0; i < len(boxes); i += columns {
		end := min(i+columns, len(boxes))
		row := lipgloss.JoinHorizontal(lipgloss.Top,
			withGaps(boxes[i:end], cardGap)...)
		rows = append(rows, row)
	}
	return strings.Join(rows, "\n")
}

// withGaps inserts a spacer column between the boxes of a row.
func withGaps(boxes []string, gap int) []string {
	if gap <= 0 || len(boxes) < 2 {
		return boxes
	}
	spacer := strings.Repeat(" ", gap)
	out := make([]string, 0, len(boxes)*2-1)
	for i, b := range boxes {
		if i > 0 {
			out = append(out, spacer)
		}
		out = append(out, b)
	}
	return out
}

// card renders one panel: a titled, bordered box with a verdict glyph, the
// summary, as many detail lines as the interior budget allows, and the managing
// tool at the foot. interior is the number of text rows the box may hold, so
// the grid stays inside the screen.
func (a *app) card(card router.Card, selected bool, width, interior int) string {
	inner := width - 4 // border (2) + padding (2)
	if inner < 8 {
		inner = 8
	}

	statusStyle := a.styleFor(card.Status)
	title := statusStyle.Render(glyph(card.Status)+" ") + a.theme.Title.Render(card.Title)

	// The title and the foot are always shown; the rest of the budget goes to
	// the summary and the detail lines, in that order.
	body := []string{a.theme.Muted.Render(ui.Truncate(card.Summary, inner))}
	for _, line := range card.Lines {
		body = append(body, a.theme.Base.Render(ui.Truncate(line, inner)))
	}
	budget := max(interior-2, 1)
	if len(body) > budget {
		body = body[:budget-1]
		body = append(body, a.theme.Muted.Render("…"))
	}

	lines := append([]string{title}, body...)
	lines = append(lines, a.toolFoot(card, inner))

	border := lipgloss.RoundedBorder()
	box := lipgloss.NewStyle().
		Border(border).
		Padding(0, 1).
		Width(width - 2).
		Height(interior)
	if selected {
		box = box.BorderForeground(a.theme.Accent.GetForeground())
	} else {
		box = box.BorderForeground(a.theme.Border.GetForeground())
	}
	return box.Render(strings.Join(lines, "\n"))
}

// toolFoot renders the "managed by" line: the tool that owns the card and
// whether ENTER can open it.
func (a *app) toolFoot(card router.Card, width int) string {
	if card.ToolInstalled {
		return a.theme.OK.Render(ui.Truncate("↵ "+card.Tool, width))
	}
	return a.theme.Muted.Render(ui.Truncate(card.Tool+" (not installed)", width))
}

// styleFor maps a verdict to a colour.
func (a *app) styleFor(status router.Status) lipgloss.Style {
	switch status {
	case router.StatusOK:
		return a.theme.OK
	case router.StatusWarn:
		return a.theme.Warn
	case router.StatusUnknown:
		return a.theme.Muted
	default:
		return a.theme.Info
	}
}

// glyph is the one-character verdict badge.
func glyph(status router.Status) string {
	switch status {
	case router.StatusOK:
		return "●"
	case router.StatusWarn:
		return "▲"
	case router.StatusUnknown:
		return "?"
	default:
		return "•"
	}
}

// shortHelpKeys is the single-line hint bar.
func shortHelpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "↑/↓", Desc: "select card"},
		{Key: "↵", Desc: "open tool"},
		{Key: "w", Desc: "roles"},
		{Key: "B", Desc: "backup"},
		{Key: "r", Desc: "refresh"},
		{Key: "?", Desc: "help"},
		{Key: "q", Desc: "quit"},
	}
}

// helpKeys is the full key list.
func helpKeys() []ui.KeyHint {
	return []ui.KeyHint{
		{Key: "↑/k, ↓/j", Desc: "select a card"},
		{Key: "tab / shift+tab", Desc: "next / previous card"},
		{Key: "g / G", Desc: "first / last card"},
		{Key: "enter", Desc: "open the tool that manages the selected card"},
		{Key: "w", Desc: "roles wizard: assign the WAN/LAN roles (router profile)"},
		{Key: "B", Desc: "backup: export an artifact, or restore one (typed confirm)"},
		{Key: "R", Desc: "reboot the router (typed confirm)"},
		{Key: "P", Desc: "power the router off (typed confirm)"},
		{Key: "r / ctrl+r", Desc: "read the router again now"},
		{Key: "?", Desc: "this help"},
		{Key: "q", Desc: "quit"},
		{Key: "", Desc: ""},
		{Key: "note", Desc: "every mutation shows its exact command and asks first;"},
		{Key: "", Desc: "the cards themselves stay read-only and hand off to their tools"},
	}
}
