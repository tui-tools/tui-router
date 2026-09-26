package main

import (
	"context"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/tui-tools/tui-kit/theme"
	"github.com/tui-tools/tui-router/internal/router"
)

func TestGridColumns(t *testing.T) {
	cases := []struct{ width, cards, want int }{
		{80, 7, 2},
		{104, 7, 3}, // three 34-wide cards and two gaps fill 104 exactly
		{120, 7, 3},
		{200, 7, 5},
		{30, 7, 1},
		{120, 2, 2},
		{120, 0, 1},
	}
	for _, tc := range cases {
		if got := gridColumns(tc.width, tc.cards); got != tc.want {
			t.Errorf("gridColumns(%d, %d) = %d, want %d", tc.width, tc.cards, got, tc.want)
		}
	}
}

// Every card, the Tailnet one included, is on screen at the family's two
// reference widths and the screenshot size, and no row is wider than the
// terminal.
func TestGridFitsEveryCard(t *testing.T) {
	for _, size := range []struct{ w, h int }{{80, 24}, {104, 26}, {120, 30}} {
		fake := router.NewFake()
		a := newApp(fake, theme.New(), nil)
		a.width, a.height = size.w, size.h
		snap, _ := fake.Read(context.Background())
		a.loading = false
		a.cur = &snap
		a.rebuild()

		grid := a.grid()
		for _, card := range a.cards {
			if !strings.Contains(grid, card.Title) {
				t.Errorf("%dx%d: card %q is not on screen", size.w, size.h, card.Title)
			}
		}
		for i, line := range strings.Split(grid, "\n") {
			if w := lipgloss.Width(line); w > size.w {
				t.Errorf("%dx%d: grid row %d is %d wide", size.w, size.h, i, w)
			}
		}
		if lines := strings.Count(a.View(), "\n") + 1; lines > size.h {
			t.Errorf("%dx%d: the screen is %d lines tall", size.w, size.h, lines)
		}
	}
}
